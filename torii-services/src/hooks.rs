//! Transaction-aware lifecycle hooks for Torii operations.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use torii_core::{
    Session, TransactionAdapter, TransactionError, TransactionOperation, User, UserId,
    repositories::{
        SessionRepository, TokenRepository, TransactionBruteForceRepository,
        TransactionOAuthRepository, TransactionPasskeyRepository, TransactionPasswordRepository,
        TransactionRepositoryView, TransactionSessionRepository, TransactionUserRepository,
        UserRepository,
    },
    session::SessionToken,
    storage::{NewUser, SecureToken, TokenPurpose},
    validation::validate_email,
    validation::validate_password,
};

// ---------------------------------------------------------------------------
// Error and decision types
// ---------------------------------------------------------------------------

pub use torii_core::TransactionError as HookError;

/// Controls whether an operation continues after a before-hook decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookDecision {
    /// Continue the operation.
    Continue,
    /// Abort the operation with an application-defined reason.
    Reject { code: String, message: String },
}

// ---------------------------------------------------------------------------
// Hook contexts — user lifecycle
// ---------------------------------------------------------------------------

/// Context supplied before user registration.
#[derive(Debug, Clone)]
pub struct BeforeUserRegistration {
    pub email: String,
    pub name: Option<String>,
}

/// Context supplied after user registration.
#[derive(Debug, Clone)]
pub struct AfterUserRegistration {
    pub user: User,
}

/// Context supplied before user update.
#[derive(Debug, Clone)]
pub struct BeforeUserUpdate {
    pub user: User,
}

/// Context supplied after user update.
#[derive(Debug, Clone)]
pub struct AfterUserUpdate {
    pub user: User,
}

/// Context supplied before user deletion.
#[derive(Debug, Clone)]
pub struct BeforeUserDeletion {
    pub user_id: UserId,
}

/// Context supplied after user deletion.
#[derive(Debug, Clone)]
pub struct AfterUserDeletion {
    pub user_id: UserId,
}

// ---------------------------------------------------------------------------
// Hook contexts — session lifecycle
// ---------------------------------------------------------------------------

/// Context supplied before session creation.
#[derive(Debug, Clone)]
pub struct BeforeSessionCreation {
    pub user_id: UserId,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

/// Context supplied after session creation.
#[derive(Debug, Clone)]
pub struct AfterSessionCreation {
    pub user_id: UserId,
    pub session: Session,
}

/// Context supplied before session deletion.
#[derive(Debug, Clone)]
pub struct BeforeSessionDeletion {
    pub token: SessionToken,
}

/// Context supplied after session deletion.
#[derive(Debug, Clone)]
pub struct AfterSessionDeletion {
    pub user_id: UserId,
    pub token: SessionToken,
}

/// Context supplied before all sessions for a user are cleared.
#[derive(Debug, Clone)]
pub struct BeforeSessionsClear {
    pub user_id: UserId,
}

/// Context supplied after all sessions for a user are cleared.
#[derive(Debug, Clone)]
pub struct AfterSessionsClear {
    pub user_id: UserId,
}

/// Context supplied after a session is refreshed.
#[derive(Debug, Clone)]
pub struct AfterSessionRefresh {
    pub user_id: UserId,
    pub session: Session,
}

// ---------------------------------------------------------------------------
// Hook contexts — password authentication
// ---------------------------------------------------------------------------

/// Context supplied before password-based registration.
#[derive(Debug, Clone)]
pub struct BeforePasswordRegistration {
    pub email: String,
}

/// Context supplied after password-based registration.
#[derive(Debug, Clone)]
pub struct AfterPasswordRegistration {
    pub user_id: UserId,
}

/// Context supplied before password authentication.
#[derive(Debug, Clone)]
pub struct BeforePasswordAuthentication {
    pub email: String,
}

/// Context supplied after password authentication.
#[derive(Debug, Clone)]
pub struct AfterPasswordAuthentication {
    pub user_id: UserId,
}

#[derive(Debug)]
pub struct BruteForceOutcome {
    pub email: String,
    pub ip_address: Option<String>,
    pub failed_attempts: u32,
    pub locked: bool,
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PasswordLoginOutcome {
    Authenticated { user: User, session: Session },
    InvalidCredentials(BruteForceOutcome),
    Locked(BruteForceOutcome),
}

#[derive(Debug)]
pub struct PasswordResetOutcome {
    pub user: User,
    pub account_was_locked: bool,
}

#[derive(Debug)]
pub struct PasswordRegistrationOutcome {
    pub user: User,
    pub password_created: bool,
}

#[derive(Debug)]
pub struct SessionDeletionOutcome {
    pub session: Session,
}

#[derive(Debug)]
pub struct PasskeyRemovalOutcome {
    pub user_id: UserId,
}

/// Authenticates a user with a password inside the active transaction.
pub struct AuthenticatePasswordOperation<U, P> {
    pub user_repository: Arc<U>,
    pub password_repository: Arc<P>,
    pub hooks: Arc<HookRegistry>,
    pub email: String,
    pub password: String,
}

pub struct CompletePasswordLoginOperation<U, P, B, S, R> {
    pub user_repository: Arc<U>,
    pub password_repository: Arc<P>,
    pub brute_force_repository: Arc<B>,
    pub session_repository: Arc<S>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub email: String,
    pub password: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub expires_in: chrono::Duration,
    pub lockout_period: chrono::Duration,
    pub lockout_duration: chrono::Duration,
    pub max_failed_attempts: u32,
}

impl<
    U: UserRepository + 'static,
    P: torii_core::repositories::PasswordRepository + 'static,
    B: torii_core::repositories::BruteForceProtectionRepository + 'static,
    S: SessionRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
> TransactionOperation<PasswordLoginOutcome> for CompletePasswordLoginOperation<U, P, B, S, R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<PasswordLoginOutcome, TransactionError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let stats = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .brute_force()
                    .get_attempt_stats(&self.email, chrono::Utc::now() - self.lockout_period)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
            };
            let existing = BruteForceOutcome {
                email: self.email.clone(),
                ip_address: self.ip_address.clone(),
                failed_attempts: stats.count,
                locked: stats.count >= self.max_failed_attempts,
                locked_until: if stats.count >= self.max_failed_attempts {
                    Some(chrono::Utc::now() + self.lockout_duration)
                } else {
                    None
                },
            };
            self.hooks
                .after_brute_force_check(
                    &AfterBruteForceCheck {
                        email: self.email.clone(),
                        status: torii_core::storage::LockoutStatus {
                            email: self.email.clone(),
                            failed_attempts: stats.count,
                            is_locked: existing.locked,
                            locked_until: existing.locked_until,
                        },
                    },
                    tx,
                )
                .await?;
            if existing.locked {
                return Ok(PasswordLoginOutcome::Locked(existing));
            }
            let mut check = BeforePasswordAuthentication {
                email: self.email.clone(),
            };
            self.hooks
                .before_password_authentication(&mut check, tx)
                .await?;
            let (user, hash) = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                let user = repositories
                    .users()
                    .find_by_email(&self.email)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .ok_or(TransactionError::InvalidCredentials)?;
                let hash = repositories
                    .passwords()
                    .get_password_hash(&user.id)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .ok_or(TransactionError::InvalidCredentials)?;
                (user, hash)
            };
            if password_auth::verify_password(&self.password, &hash).is_err() {
                let mut record = BeforeBruteForceRecord {
                    email: self.email.clone(),
                    ip_address: self.ip_address.clone(),
                };
                self.hooks
                    .before_brute_force_record(&mut record, tx)
                    .await?;
                self.brute_force_repository
                    .record_failed_attempt(tx, &self.email, self.ip_address.as_deref())
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                let updated = {
                    let mut repositories = self
                        .repositories
                        .transactional(tx)
                        .map_err(|e| TransactionError::Failed(e.to_string()))?;
                    repositories
                        .brute_force()
                        .get_attempt_stats(&self.email, chrono::Utc::now() - self.lockout_period)
                        .await
                        .map_err(|e| TransactionError::Failed(e.to_string()))?
                };
                let status = torii_core::storage::LockoutStatus {
                    email: self.email.clone(),
                    failed_attempts: updated.count,
                    is_locked: updated.count >= self.max_failed_attempts,
                    locked_until: if updated.count >= self.max_failed_attempts {
                        Some(chrono::Utc::now() + self.lockout_duration)
                    } else {
                        None
                    },
                };
                if status.is_locked {
                    self.brute_force_repository
                        .set_locked_at(tx, &self.email, Some(chrono::Utc::now()))
                        .await
                        .map_err(|e| TransactionError::Failed(e.to_string()))?;
                }
                self.hooks
                    .after_brute_force_record(
                        &AfterBruteForceRecord {
                            email: self.email.clone(),
                            status: status.clone(),
                        },
                        tx,
                    )
                    .await?;
                let outcome = BruteForceOutcome {
                    email: self.email,
                    ip_address: self.ip_address,
                    failed_attempts: updated.count,
                    locked: status.is_locked,
                    locked_until: status.locked_until,
                };
                return Ok(if outcome.locked {
                    PasswordLoginOutcome::Locked(outcome)
                } else {
                    PasswordLoginOutcome::InvalidCredentials(outcome)
                });
            }
            self.brute_force_repository
                .clear_attempts(tx, &self.email)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.brute_force_repository
                .set_locked_at(tx, &self.email, None)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_brute_force_reset(
                    &AfterBruteForceReset {
                        email: self.email.clone(),
                    },
                    tx,
                )
                .await?;
            self.hooks
                .after_password_authentication(
                    &AfterPasswordAuthentication {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            let mut session_context = BeforeSessionCreation {
                user_id: user.id.clone(),
                user_agent: self.user_agent.clone(),
                ip_address: self.ip_address.clone(),
            };
            self.hooks
                .before_session_creation(&mut session_context, tx)
                .await?;
            let session = Session::builder()
                .token(SessionToken::new_random())
                .user_id(user.id.clone())
                .user_agent(self.user_agent)
                .ip_address(self.ip_address)
                .expires_at(chrono::Utc::now() + self.expires_in)
                .build()
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let session = self
                .session_repository
                .create(tx, session)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_session_creation(
                    &AfterSessionCreation {
                        user_id: user.id.clone(),
                        session: session.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(PasswordLoginOutcome::Authenticated { user, session })
        })
    }
}

pub struct ChangePasswordOperation<R> {
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
    pub old_password: String,
    pub new_password: String,
}

pub struct CompletePasswordChangeOperation<P, S, R> {
    pub password_repository: Arc<P>,
    pub session_repository: Arc<S>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
    pub old_password: String,
    pub new_password: String,
}

impl<
    P: torii_core::repositories::PasswordRepository + 'static,
    S: SessionRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
> TransactionOperation<()> for CompletePasswordChangeOperation<P, S, R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let current = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .passwords()
                    .get_password_hash(&self.user_id)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .ok_or_else(|| TransactionError::Failed("Invalid credentials".into()))?
            };
            if password_auth::verify_password(&self.old_password, &current).is_err() {
                return Err(TransactionError::Failed("Invalid credentials".into()));
            }
            validate_password(&self.new_password)
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .before_password_change(
                    &mut BeforePasswordChange {
                        user_id: self.user_id.clone(),
                    },
                    tx,
                )
                .await?;
            let hash = password_auth::generate_hash(&self.new_password);
            {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .passwords()
                    .set_password_hash(&self.user_id, &hash)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
            }
            self.hooks
                .after_password_change(
                    &AfterPasswordChange {
                        user_id: self.user_id.clone(),
                    },
                    tx,
                )
                .await?;
            self.hooks
                .before_sessions_clear(
                    &mut BeforeSessionsClear {
                        user_id: self.user_id.clone(),
                    },
                    tx,
                )
                .await?;
            self.session_repository
                .delete_by_user_id(tx, &self.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_sessions_clear(
                    &AfterSessionsClear {
                        user_id: self.user_id,
                    },
                    tx,
                )
                .await?;
            Ok(())
        })
    }
}

pub struct ResetPasswordOperation<U, P, T, R> {
    pub user_repository: Arc<U>,
    pub password_repository: Arc<P>,
    pub token_repository: Arc<T>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub token: String,
    pub new_password: String,
}

pub struct CompletePasswordResetOperation<U, P, T, B, S, R> {
    pub user_repository: Arc<U>,
    pub password_repository: Arc<P>,
    pub token_repository: Arc<T>,
    pub brute_force_repository: Arc<B>,
    pub session_repository: Arc<S>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub token: String,
    pub new_password: String,
}

impl<
    U: UserRepository + 'static,
    P: torii_core::repositories::PasswordRepository + 'static,
    T: TokenRepository + 'static,
    B: torii_core::repositories::BruteForceProtectionRepository + 'static,
    S: SessionRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
> TransactionOperation<PasswordResetOutcome> for CompletePasswordResetOperation<U, P, T, B, S, R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<PasswordResetOutcome, TransactionError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            validate_password(&self.new_password)
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let token = self
                .token_repository
                .verify_token(tx, &self.token, TokenPurpose::PasswordReset)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?
                .ok_or_else(|| TransactionError::Failed("Invalid credentials".into()))?;
            let (user, account_was_locked) = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                let user = repositories
                    .users()
                    .find_by_id(&token.user_id)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .ok_or_else(|| TransactionError::Failed("Invalid credentials".into()))?;
                let locked = repositories
                    .brute_force()
                    .get_locked_at(&user.email)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .is_some();
                (user, locked)
            };
            let hash = password_auth::generate_hash(&self.new_password);
            {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .passwords()
                    .set_password_hash(&user.id, &hash)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
            }
            let mut reset = BeforeBruteForceReset {
                email: user.email.clone(),
            };
            self.hooks.before_brute_force_reset(&mut reset, tx).await?;
            self.brute_force_repository
                .clear_attempts(tx, &user.email)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.brute_force_repository
                .set_locked_at(tx, &user.email, None)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_brute_force_reset(
                    &AfterBruteForceReset {
                        email: user.email.clone(),
                    },
                    tx,
                )
                .await?;
            self.hooks
                .before_sessions_clear(
                    &mut BeforeSessionsClear {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            self.session_repository
                .delete_by_user_id(tx, &user.id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_sessions_clear(
                    &AfterSessionsClear {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            self.hooks
                .after_password_reset_completion(
                    &AfterPasswordResetCompletion {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(PasswordResetOutcome {
                user,
                account_was_locked,
            })
        })
    }
}

pub struct RequestPasswordResetOperation<U, T> {
    pub user_repository: Arc<U>,
    pub token_repository: Arc<T>,
    pub hooks: Arc<HookRegistry>,
    pub email: String,
    pub expires_in: chrono::Duration,
}

impl<U: UserRepository + 'static, T: TokenRepository + 'static>
    TransactionOperation<Option<(User, String)>> for RequestPasswordResetOperation<U, T>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<(User, String)>, TransactionError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let Some(user) = self
                .user_repository
                .find_by_email(&self.email)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?
            else {
                return Ok(None);
            };
            let mut context = BeforePasswordResetRequest { email: self.email };
            self.hooks
                .before_password_reset_request(&mut context, tx)
                .await?;
            let token = self
                .token_repository
                .create_token(tx, &user.id, TokenPurpose::PasswordReset, self.expires_in)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let value = token
                .token()
                .ok_or_else(|| TransactionError::Failed("Password reset token unavailable".into()))?
                .to_string();
            self.hooks
                .after_password_reset_request(
                    &AfterPasswordResetRequest {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(Some((user, value)))
        })
    }
}

impl<
    U: UserRepository + 'static,
    P: torii_core::repositories::PasswordRepository + 'static,
    T: TokenRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
> TransactionOperation<User> for ResetPasswordOperation<U, P, T, R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<User, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            validate_password(&self.new_password)
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let token = self
                .token_repository
                .verify_token(tx, &self.token, TokenPurpose::PasswordReset)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?
                .ok_or_else(|| TransactionError::Failed("Invalid credentials".into()))?;
            let user = self
                .user_repository
                .find_by_id(&token.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?
                .ok_or_else(|| TransactionError::Failed("Invalid credentials".into()))?;
            let hash = password_auth::generate_hash(&self.new_password);
            {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .passwords()
                    .set_password_hash(&user.id, &hash)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
            }
            self.hooks
                .after_password_reset_completion(
                    &AfterPasswordResetCompletion {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(user)
        })
    }
}

impl<R: torii_core::repositories::TransactionalRepositoryProvider + 'static> TransactionOperation<()>
    for ChangePasswordOperation<R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let hash = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .passwords()
                    .get_password_hash(&self.user_id)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .ok_or_else(|| TransactionError::Failed("Invalid credentials".into()))?
            };
            if password_auth::verify_password(&self.old_password, &hash).is_err() {
                return Err(TransactionError::Failed("Invalid credentials".into()));
            }
            validate_password(&self.new_password)
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let mut context = BeforePasswordChange {
                user_id: self.user_id.clone(),
            };
            self.hooks.before_password_change(&mut context, tx).await?;
            let new_hash = password_auth::generate_hash(&self.new_password);
            {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .passwords()
                    .set_password_hash(&self.user_id, &new_hash)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
            }
            self.hooks
                .after_password_change(
                    &AfterPasswordChange {
                        user_id: self.user_id,
                    },
                    tx,
                )
                .await?;
            Ok(())
        })
    }
}

/// Clears failed login state within the active transaction.
pub struct ResetBruteForceOperation<R> {
    pub repository: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub email: String,
}

pub struct RecordBruteForceOperation<R> {
    pub repository: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub email: String,
    pub ip_address: Option<String>,
    pub lockout_period: chrono::Duration,
    pub lockout_duration: chrono::Duration,
    pub max_failed_attempts: u32,
}

pub struct CheckBruteForceOperation<R> {
    pub repository: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub email: String,
    pub lockout_period: chrono::Duration,
    pub lockout_duration: chrono::Duration,
    pub max_failed_attempts: u32,
}

impl<R: torii_core::repositories::TransactionalRepositoryProvider + 'static>
    TransactionOperation<torii_core::storage::LockoutStatus> for CheckBruteForceOperation<R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<torii_core::storage::LockoutStatus, TransactionError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let mut context = BeforeBruteForceCheck {
                email: self.email.clone(),
            };
            self.hooks
                .before_brute_force_check(&mut context, tx)
                .await?;
            let stats = {
                let mut repositories = self
                    .repository
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .brute_force()
                    .get_attempt_stats(&self.email, chrono::Utc::now() - self.lockout_period)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
            };
            let status = torii_core::storage::LockoutStatus {
                email: self.email.clone(),
                failed_attempts: stats.count,
                is_locked: stats.count >= self.max_failed_attempts,
                locked_until: if stats.count >= self.max_failed_attempts {
                    Some(chrono::Utc::now() + self.lockout_duration)
                } else {
                    None
                },
            };
            self.hooks
                .after_brute_force_check(
                    &AfterBruteForceCheck {
                        email: self.email,
                        status: status.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(status)
        })
    }
}

impl<R: torii_core::repositories::TransactionalRepositoryProvider + 'static>
    TransactionOperation<torii_core::storage::LockoutStatus> for RecordBruteForceOperation<R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<torii_core::storage::LockoutStatus, TransactionError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let mut context = BeforeBruteForceRecord {
                email: self.email.clone(),
                ip_address: self.ip_address.clone(),
            };
            self.hooks
                .before_brute_force_record(&mut context, tx)
                .await?;
            let stats = {
                let mut repositories = self
                    .repository
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .brute_force()
                    .record_failed_attempt(&self.email, self.ip_address.as_deref())
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .brute_force()
                    .get_attempt_stats(&self.email, chrono::Utc::now() - self.lockout_period)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
            };
            let status = torii_core::storage::LockoutStatus {
                email: self.email.clone(),
                failed_attempts: stats.count,
                is_locked: stats.count >= self.max_failed_attempts,
                locked_until: if stats.count >= self.max_failed_attempts {
                    Some(chrono::Utc::now() + self.lockout_duration)
                } else {
                    None
                },
            };
            if status.is_locked {
                let mut repositories = self
                    .repository
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .brute_force()
                    .set_locked_at(&self.email, Some(chrono::Utc::now()))
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
            }
            self.hooks
                .after_brute_force_record(
                    &AfterBruteForceRecord {
                        email: self.email,
                        status: status.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(status)
        })
    }
}

impl<R: torii_core::repositories::TransactionalRepositoryProvider + 'static> TransactionOperation<()>
    for ResetBruteForceOperation<R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut context = BeforeBruteForceReset {
                email: self.email.clone(),
            };
            self.hooks
                .before_brute_force_reset(&mut context, tx)
                .await?;
            {
                let mut repositories = self
                    .repository
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .brute_force()
                    .clear_attempts(&self.email)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .brute_force()
                    .set_locked_at(&self.email, None)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
            }
            self.hooks
                .after_brute_force_reset(&AfterBruteForceReset { email: self.email }, tx)
                .await?;
            Ok(())
        })
    }
}

impl<U: UserRepository + 'static, P: torii_core::repositories::PasswordRepository + 'static>
    TransactionOperation<User> for AuthenticatePasswordOperation<U, P>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<User, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut context = BeforePasswordAuthentication {
                email: self.email.clone(),
            };
            self.hooks
                .before_password_authentication(&mut context, tx)
                .await?;
            let user = self
                .user_repository
                .find_by_email(&self.email)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?
                .ok_or_else(|| TransactionError::Failed("Invalid credentials".to_string()))?;
            let hash = self
                .password_repository
                .get_password_hash(&user.id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?
                .ok_or_else(|| TransactionError::Failed("Invalid credentials".to_string()))?;
            if password_auth::verify_password(&self.password, &hash).is_err() {
                return Err(TransactionError::Failed("Invalid credentials".to_string()));
            }
            self.hooks
                .after_password_authentication(
                    &AfterPasswordAuthentication {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(user)
        })
    }
}

/// Context supplied before a password change.
#[derive(Debug, Clone)]
pub struct BeforePasswordChange {
    pub user_id: UserId,
}

/// Context supplied after a password change.
#[derive(Debug, Clone)]
pub struct AfterPasswordChange {
    pub user_id: UserId,
}

/// Context supplied after a password is removed.
#[derive(Debug, Clone)]
pub struct AfterPasswordRemoval {
    pub user_id: UserId,
}

// ---------------------------------------------------------------------------
// Hook contexts — password reset
// ---------------------------------------------------------------------------

/// Context supplied before a password reset is requested.
#[derive(Debug, Clone)]
pub struct BeforePasswordResetRequest {
    pub email: String,
}

/// Context supplied after a password reset is requested.
#[derive(Debug, Clone)]
pub struct AfterPasswordResetRequest {
    pub user_id: UserId,
}

/// Context supplied after a password reset is completed.
#[derive(Debug, Clone)]
pub struct AfterPasswordResetCompletion {
    pub user_id: UserId,
}

// ---------------------------------------------------------------------------
// Hook contexts — brute-force protection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BeforeBruteForceCheck {
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct AfterBruteForceCheck {
    pub email: String,
    pub status: torii_core::storage::LockoutStatus,
}

#[derive(Debug, Clone)]
pub struct BeforeBruteForceRecord {
    pub email: String,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AfterBruteForceRecord {
    pub email: String,
    pub status: torii_core::storage::LockoutStatus,
}

#[derive(Debug, Clone)]
pub struct BeforeBruteForceReset {
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct AfterBruteForceReset {
    pub email: String,
}

pub struct CreateSessionOperation<S> {
    pub repository: Arc<S>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub expires_in: chrono::Duration,
}

impl<S: SessionRepository + 'static> TransactionOperation<Session> for CreateSessionOperation<S> {
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Session, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut context = BeforeSessionCreation {
                user_id: self.user_id.clone(),
                user_agent: self.user_agent.clone(),
                ip_address: self.ip_address.clone(),
            };
            self.hooks.before_session_creation(&mut context, tx).await?;
            let session = Session::builder()
                .token(SessionToken::new_random())
                .user_id(self.user_id.clone())
                .user_agent(self.user_agent)
                .ip_address(self.ip_address)
                .expires_at(chrono::Utc::now() + self.expires_in)
                .build()
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let session = self
                .repository
                .create(tx, session)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_session_creation(
                    &AfterSessionCreation {
                        user_id: self.user_id,
                        session: session.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(session)
        })
    }
}

pub struct DeleteSessionOperation<S, R> {
    pub repository: Arc<S>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub token: SessionToken,
}
impl<
    S: SessionRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
> TransactionOperation<SessionDeletionOutcome> for DeleteSessionOperation<S, R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<SessionDeletionOutcome, TransactionError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let session = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .sessions()
                    .find_by_token(&self.token)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .ok_or_else(|| TransactionError::Failed("Session not found".into()))?
            };
            self.hooks
                .before_session_deletion(
                    &mut BeforeSessionDeletion {
                        token: self.token.clone(),
                    },
                    tx,
                )
                .await?;
            self.repository
                .delete(tx, &self.token)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_session_deletion(
                    &AfterSessionDeletion {
                        user_id: session.user_id.clone(),
                        token: self.token,
                    },
                    tx,
                )
                .await?;
            Ok(SessionDeletionOutcome { session })
        })
    }
}

pub struct ClearSessionsOperation<S> {
    pub repository: Arc<S>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
}

pub struct RefreshSessionOperation<S> {
    pub repository: Arc<S>,
    pub hooks: Arc<HookRegistry>,
    pub token: SessionToken,
    pub duration: chrono::Duration,
}

impl<S: SessionRepository + 'static> TransactionOperation<Session> for RefreshSessionOperation<S> {
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Session, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let session = self
                .repository
                .refresh(tx, &self.token, self.duration)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_session_refresh(
                    &AfterSessionRefresh {
                        user_id: session.user_id.clone(),
                        session: session.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(session)
        })
    }
}
impl<S: SessionRepository + 'static> TransactionOperation<()> for ClearSessionsOperation<S> {
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.hooks
                .before_sessions_clear(
                    &mut BeforeSessionsClear {
                        user_id: self.user_id.clone(),
                    },
                    tx,
                )
                .await?;
            self.repository
                .delete_by_user_id(tx, &self.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_sessions_clear(
                    &AfterSessionsClear {
                        user_id: self.user_id,
                    },
                    tx,
                )
                .await?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Hook contexts — OAuth
// ---------------------------------------------------------------------------

/// Context supplied before OAuth authentication.
#[derive(Debug, Clone)]
pub struct BeforeOAuthAuthentication {
    pub email: String,
    pub provider: String,
}

/// Context supplied after OAuth authentication.
#[derive(Debug, Clone)]
pub struct AfterOAuthAuthentication {
    pub user_id: UserId,
    pub provider: String,
}

/// Context supplied before an OAuth account is linked.
#[derive(Debug, Clone)]
pub struct BeforeOAuthAccountLink {
    pub user_id: UserId,
    pub provider: String,
}

/// Context supplied after an OAuth account is linked.
#[derive(Debug, Clone)]
pub struct AfterOAuthAccountLink {
    pub user_id: UserId,
    pub provider: String,
}

/// Context supplied before an OAuth account is unlinked.
#[derive(Debug, Clone)]
pub struct BeforeOAuthAccountUnlink {
    pub user_id: UserId,
    pub provider: String,
}

/// Context supplied after an OAuth account is unlinked.
#[derive(Debug, Clone)]
pub struct AfterOAuthAccountUnlink {
    pub user_id: UserId,
    pub provider: String,
}

// ---------------------------------------------------------------------------
// Hook contexts — passkeys
// ---------------------------------------------------------------------------

/// Context supplied before a passkey credential is registered.
#[derive(Debug, Clone)]
pub struct BeforePasskeyRegistration {
    pub user_id: UserId,
}

/// Context supplied after a passkey credential is registered.
#[derive(Debug, Clone)]
pub struct AfterPasskeyRegistration {
    pub user_id: UserId,
}

/// Context supplied after passkey authentication.
#[derive(Debug, Clone)]
pub struct AfterPasskeyAuthentication {
    pub user_id: UserId,
}

/// Context supplied after a passkey credential is removed.
#[derive(Debug, Clone)]
pub struct AfterPasskeyRemoval {
    pub user_id: UserId,
}

// ---------------------------------------------------------------------------
// Hook contexts — magic links
// ---------------------------------------------------------------------------

/// Context supplied before a magic link is sent.
#[derive(Debug, Clone)]
pub struct BeforeMagicLinkSend {
    pub user_id: UserId,
    pub email: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Context supplied after magic-link authentication.
#[derive(Debug, Clone)]
pub struct AfterMagicLinkAuthentication {
    pub user_id: UserId,
}

/// Creates a user when necessary and stores a magic-link token atomically.
pub struct GenerateMagicLinkOperation<U, T, R> {
    pub user_repository: Arc<U>,
    pub token_repository: Arc<T>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub email: String,
    pub expires_in: chrono::Duration,
}

impl<
    U: UserRepository + 'static,
    T: TokenRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
> TransactionOperation<(SecureToken, bool, User)> for GenerateMagicLinkOperation<U, T, R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(SecureToken, bool, User), TransactionError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            validate_email(&self.email).map_err(|e| TransactionError::Failed(e.to_string()))?;
            let existing_user = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories.users().find_by_email(&self.email).await
            }
            .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let (user, user_created) = if let Some(user) = existing_user {
                (user, false)
            } else {
                let new_user = NewUser::builder()
                    .id(UserId::new_random())
                    .email(self.email.clone())
                    .build()
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                (
                    repositories
                        .users()
                        .create(new_user)
                        .await
                        .map_err(|e| TransactionError::Failed(e.to_string()))?,
                    true,
                )
            };
            let expires_at = chrono::Utc::now() + self.expires_in;
            let mut context = BeforeMagicLinkSend {
                user_id: user.id.clone(),
                email: self.email,
                expires_at,
            };
            self.hooks.before_magic_link_send(&mut context, tx).await?;
            let token = self
                .token_repository
                .create_token(tx, &user.id, TokenPurpose::MagicLink, self.expires_in)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            Ok((token, user_created, user))
        })
    }
}

/// Consumes a magic-link token and loads its user atomically.
pub struct AuthenticateMagicLinkOperation<U, T> {
    pub user_repository: Arc<U>,
    pub token_repository: Arc<T>,
    pub hooks: Arc<HookRegistry>,
    pub token: String,
}

pub struct CompleteMagicLinkAuthenticationOperation<U, T, S, R> {
    pub user_repository: Arc<U>,
    pub token_repository: Arc<T>,
    pub session_repository: Arc<S>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub token: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub expires_in: chrono::Duration,
}

impl<
    U: UserRepository + 'static,
    T: TokenRepository + 'static,
    S: SessionRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
> TransactionOperation<(User, Session)> for CompleteMagicLinkAuthenticationOperation<U, T, S, R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(User, Session), TransactionError>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            let token = self
                .token_repository
                .verify_token(tx, &self.token, TokenPurpose::MagicLink)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?
                .ok_or_else(|| TransactionError::Failed("Invalid magic token".into()))?;
            let user = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .users()
                    .find_by_id(&token.user_id)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .ok_or_else(|| TransactionError::Failed("User not found".into()))?
            };
            self.hooks
                .after_magic_link_authentication(
                    &AfterMagicLinkAuthentication {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            let mut session_context = BeforeSessionCreation {
                user_id: user.id.clone(),
                user_agent: self.user_agent.clone(),
                ip_address: self.ip_address.clone(),
            };
            self.hooks
                .before_session_creation(&mut session_context, tx)
                .await?;
            let session = Session::builder()
                .token(SessionToken::new_random())
                .user_id(user.id.clone())
                .user_agent(self.user_agent)
                .ip_address(self.ip_address)
                .expires_at(chrono::Utc::now() + self.expires_in)
                .build()
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let session = self
                .session_repository
                .create(tx, session)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_session_creation(
                    &AfterSessionCreation {
                        user_id: user.id.clone(),
                        session: session.clone(),
                    },
                    tx,
                )
                .await?;
            Ok((user, session))
        })
    }
}

/// Creates an email-verification token within the active transaction.
pub struct GenerateEmailVerificationOperation<T> {
    pub token_repository: Arc<T>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
    pub expires_in: chrono::Duration,
}

impl<T: TokenRepository + 'static> TransactionOperation<SecureToken>
    for GenerateEmailVerificationOperation<T>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SecureToken, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.hooks
                .before_email_verification_request(
                    &mut BeforeEmailVerificationRequest {
                        user_id: self.user_id.clone(),
                    },
                    tx,
                )
                .await?;
            self.token_repository
                .create_token(
                    tx,
                    &self.user_id,
                    TokenPurpose::EmailVerification,
                    self.expires_in,
                )
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))
        })
    }
}

impl<U: UserRepository + 'static, T: TokenRepository + 'static> TransactionOperation<Option<User>>
    for AuthenticateMagicLinkOperation<U, T>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<User>, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let token = self
                .token_repository
                .verify_token(tx, &self.token, TokenPurpose::MagicLink)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let Some(token) = token else {
                return Ok(None);
            };
            let user = self
                .user_repository
                .find_by_id(&token.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            if let Some(user) = &user {
                self.hooks
                    .after_magic_link_authentication(
                        &AfterMagicLinkAuthentication {
                            user_id: user.id.clone(),
                        },
                        tx,
                    )
                    .await?;
            }
            Ok(user)
        })
    }
}

// ---------------------------------------------------------------------------
// Hook contexts — email verification
// ---------------------------------------------------------------------------

/// Context supplied before an email verification is requested.
#[derive(Debug, Clone)]
pub struct BeforeEmailVerificationRequest {
    pub user_id: UserId,
}

/// Context supplied after an email is verified.
#[derive(Debug, Clone)]
pub struct AfterEmailVerification {
    pub user_id: UserId,
}

// ---------------------------------------------------------------------------
// Hook contexts — brute force / security
// ---------------------------------------------------------------------------

/// Context supplied after a login attempt fails.
#[derive(Debug, Clone)]
pub struct AfterLoginFailure {
    pub email: String,
    pub failed_attempts: u32,
    pub ip_address: Option<String>,
}

/// Context supplied after an account becomes locked.
#[derive(Debug, Clone)]
pub struct AfterAccountLockout {
    pub email: String,
    pub failed_attempts: u32,
    pub locked_until: chrono::DateTime<chrono::Utc>,
}

/// Context supplied after an account is unlocked.
#[derive(Debug, Clone)]
pub struct AfterAccountUnlock {
    pub email: String,
    pub reason: torii_core::events::UnlockReason,
}

// ---------------------------------------------------------------------------
// Hook trait
// ---------------------------------------------------------------------------

/// Application lifecycle hooks for Torii operations.
///
/// All methods have default no-op implementations. Override only the hooks
/// relevant to your application. Hooks execute in registration order.
#[async_trait]
pub trait ToriiHook: Send + Sync {
    // -- user lifecycle --

    async fn before_user_registration(
        &self,
        _ctx: &mut BeforeUserRegistration,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_user_registration(
        &self,
        _ctx: &AfterUserRegistration,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_user_update(
        &self,
        _ctx: &mut BeforeUserUpdate,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_user_update(
        &self,
        _ctx: &AfterUserUpdate,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_user_deletion(
        &self,
        _ctx: &mut BeforeUserDeletion,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_user_deletion(
        &self,
        _ctx: &AfterUserDeletion,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    // -- session lifecycle --

    async fn before_session_creation(
        &self,
        _ctx: &mut BeforeSessionCreation,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_session_creation(
        &self,
        _ctx: &AfterSessionCreation,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_session_deletion(
        &self,
        _ctx: &mut BeforeSessionDeletion,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_session_deletion(
        &self,
        _ctx: &AfterSessionDeletion,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_sessions_clear(
        &self,
        _ctx: &mut BeforeSessionsClear,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_sessions_clear(
        &self,
        _ctx: &AfterSessionsClear,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn after_session_refresh(
        &self,
        _ctx: &AfterSessionRefresh,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    // -- password authentication --

    async fn before_password_registration(
        &self,
        _ctx: &mut BeforePasswordRegistration,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_password_registration(
        &self,
        _ctx: &AfterPasswordRegistration,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_password_authentication(
        &self,
        _ctx: &mut BeforePasswordAuthentication,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_password_authentication(
        &self,
        _ctx: &AfterPasswordAuthentication,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_password_change(
        &self,
        _ctx: &mut BeforePasswordChange,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_password_change(
        &self,
        _ctx: &AfterPasswordChange,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn after_password_removal(
        &self,
        _ctx: &AfterPasswordRemoval,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    // -- password reset --

    async fn before_password_reset_request(
        &self,
        _ctx: &mut BeforePasswordResetRequest,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_password_reset_request(
        &self,
        _ctx: &AfterPasswordResetRequest,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn after_password_reset_completion(
        &self,
        _ctx: &AfterPasswordResetCompletion,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    // -- OAuth --

    async fn before_oauth_authentication(
        &self,
        _ctx: &mut BeforeOAuthAuthentication,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_oauth_authentication(
        &self,
        _ctx: &AfterOAuthAuthentication,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_oauth_account_link(
        &self,
        _ctx: &mut BeforeOAuthAccountLink,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_oauth_account_link(
        &self,
        _ctx: &AfterOAuthAccountLink,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_oauth_account_unlink(
        &self,
        _ctx: &mut BeforeOAuthAccountUnlink,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_oauth_account_unlink(
        &self,
        _ctx: &AfterOAuthAccountUnlink,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    // -- passkeys --

    async fn before_passkey_registration(
        &self,
        _ctx: &mut BeforePasskeyRegistration,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_passkey_registration(
        &self,
        _ctx: &AfterPasskeyRegistration,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn after_passkey_authentication(
        &self,
        _ctx: &AfterPasskeyAuthentication,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn after_passkey_removal(
        &self,
        _ctx: &AfterPasskeyRemoval,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    // -- magic links --

    async fn before_magic_link_send(
        &self,
        _ctx: &mut BeforeMagicLinkSend,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_magic_link_authentication(
        &self,
        _ctx: &AfterMagicLinkAuthentication,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    // -- email verification --

    async fn before_email_verification_request(
        &self,
        _ctx: &mut BeforeEmailVerificationRequest,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_email_verification(
        &self,
        _ctx: &AfterEmailVerification,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    // -- brute force / security --

    async fn before_brute_force_check(
        &self,
        _ctx: &mut BeforeBruteForceCheck,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_brute_force_check(
        &self,
        _ctx: &AfterBruteForceCheck,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_brute_force_record(
        &self,
        _ctx: &mut BeforeBruteForceRecord,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_brute_force_record(
        &self,
        _ctx: &AfterBruteForceRecord,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn before_brute_force_reset(
        &self,
        _ctx: &mut BeforeBruteForceReset,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_brute_force_reset(
        &self,
        _ctx: &AfterBruteForceReset,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn after_login_failure(
        &self,
        _ctx: &AfterLoginFailure,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn after_account_lockout(
        &self,
        _ctx: &AfterAccountLockout,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }

    async fn after_account_unlock(
        &self,
        _ctx: &AfterAccountUnlock,
        _tx: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }
}

/// Transactional user registration shared by all storage backends.
pub struct RegisterUserOperation<R> {
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub new_user: NewUser,
    pub password_hash: String,
}

pub struct DeleteUserOperation<U> {
    pub user_repository: Arc<U>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
}

impl<U: UserRepository + 'static> TransactionOperation<()> for DeleteUserOperation<U> {
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.hooks
                .before_user_deletion(
                    &mut BeforeUserDeletion {
                        user_id: self.user_id.clone(),
                    },
                    tx,
                )
                .await?;
            self.user_repository
                .delete(tx, &self.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_user_deletion(
                    &AfterUserDeletion {
                        user_id: self.user_id,
                    },
                    tx,
                )
                .await?;
            Ok(())
        })
    }
}

pub struct VerifyEmailOperation<U> {
    pub user_repository: Arc<U>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
}

pub struct CompleteEmailVerificationOperation<U, T> {
    pub user_repository: Arc<U>,
    pub token_repository: Arc<T>,
    pub hooks: Arc<HookRegistry>,
    pub token: String,
}

impl<U: UserRepository + 'static, T: TokenRepository + 'static> TransactionOperation<User>
    for CompleteEmailVerificationOperation<U, T>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<User, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let token = self
                .token_repository
                .verify_token(tx, &self.token, TokenPurpose::EmailVerification)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?
                .ok_or_else(|| {
                    TransactionError::Failed("Invalid or expired email verification token".into())
                })?;
            self.user_repository
                .mark_email_verified(tx, &token.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let user = self
                .user_repository
                .find_by_id(&token.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?
                .ok_or_else(|| TransactionError::Failed("User not found".into()))?;
            self.hooks
                .after_email_verification(
                    &AfterEmailVerification {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            Ok(user)
        })
    }
}

pub struct LinkOAuthAccountOperation<O> {
    pub repository: Arc<O>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
    pub provider: String,
    pub subject: String,
}

impl<O: torii_core::repositories::OAuthRepository + 'static> TransactionOperation<()>
    for LinkOAuthAccountOperation<O>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.hooks
                .before_oauth_account_link(
                    &mut BeforeOAuthAccountLink {
                        user_id: self.user_id.clone(),
                        provider: self.provider.clone(),
                    },
                    tx,
                )
                .await?;
            self.repository
                .link_account(tx, &self.user_id, &self.provider, &self.subject)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_oauth_account_link(
                    &AfterOAuthAccountLink {
                        user_id: self.user_id,
                        provider: self.provider,
                    },
                    tx,
                )
                .await?;
            Ok(())
        })
    }
}

pub struct UnlinkOAuthAccountOperation<O> {
    pub repository: Arc<O>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
    pub provider: String,
}

pub struct StorePkceOperation<O> {
    pub repository: Arc<O>,
    pub csrf_state: String,
    pub verifier: String,
    pub expires_in: chrono::Duration,
}

impl<O: torii_core::repositories::OAuthRepository + 'static> TransactionOperation<()>
    for StorePkceOperation<O>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.repository
                .store_pkce_verifier(tx, &self.csrf_state, &self.verifier, self.expires_in)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))
        })
    }
}

pub struct ConsumePkceOperation<O> {
    pub repository: Arc<O>,
    pub csrf_state: String,
}

impl<O: torii_core::repositories::OAuthRepository + 'static> TransactionOperation<Option<String>>
    for ConsumePkceOperation<O>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<String>, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let verifier = self
                .repository
                .get_pkce_verifier(&self.csrf_state)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            if verifier.is_some() {
                self.repository
                    .delete_pkce_verifier(tx, &self.csrf_state)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
            }
            Ok(verifier)
        })
    }
}

pub struct RegisterPasskeyOperation<P> {
    pub repository: Arc<P>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub name: Option<String>,
}

impl<P: torii_core::repositories::PasskeyRepository + 'static>
    TransactionOperation<torii_core::repositories::PasskeyCredential>
    for RegisterPasskeyOperation<P>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<torii_core::repositories::PasskeyCredential, TransactionError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.hooks
                .before_passkey_registration(
                    &mut BeforePasskeyRegistration {
                        user_id: self.user_id.clone(),
                    },
                    tx,
                )
                .await?;
            let credential = self
                .repository
                .add_credential(
                    tx,
                    &self.user_id,
                    self.credential_id,
                    self.public_key,
                    self.name,
                )
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_passkey_registration(
                    &AfterPasskeyRegistration {
                        user_id: self.user_id,
                    },
                    tx,
                )
                .await?;
            Ok(credential)
        })
    }
}

pub struct RemovePasskeyOperation<P> {
    pub repository: Arc<P>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
    pub credential_id: Vec<u8>,
}
impl<P: torii_core::repositories::PasskeyRepository + 'static> TransactionOperation<()>
    for RemovePasskeyOperation<P>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.repository
                .delete_credential(tx, &self.credential_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_passkey_removal(
                    &AfterPasskeyRemoval {
                        user_id: self.user_id,
                    },
                    tx,
                )
                .await?;
            Ok(())
        })
    }
}

pub struct RemoveUserPasskeysOperation<P> {
    pub repository: Arc<P>,
    pub hooks: Arc<HookRegistry>,
    pub user_id: UserId,
}

pub struct AuthenticatePasskeyOperation<U, P> {
    pub user_repository: Arc<U>,
    pub repository: Arc<P>,
    pub hooks: Arc<HookRegistry>,
    pub credential_id: Vec<u8>,
}

pub struct CompletePasskeyAuthenticationOperation<U, P, S, R> {
    pub user_repository: Arc<U>,
    pub repository: Arc<P>,
    pub session_repository: Arc<S>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub credential_id: Vec<u8>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub expires_in: chrono::Duration,
}

impl<
    U: UserRepository + 'static,
    P: torii_core::repositories::PasskeyRepository + 'static,
    S: SessionRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
> TransactionOperation<(User, Session)> for CompletePasskeyAuthenticationOperation<U, P, S, R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(User, Session), TransactionError>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            let credential = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .passkeys()
                    .get_credential(&self.credential_id)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .ok_or_else(|| TransactionError::Failed("Invalid passkey credential".into()))?
            };
            self.repository
                .update_last_used(tx, &self.credential_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let user = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .users()
                    .find_by_id(&credential.user_id)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
                    .ok_or_else(|| TransactionError::Failed("User not found".into()))?
            };
            self.hooks
                .after_passkey_authentication(
                    &AfterPasskeyAuthentication {
                        user_id: user.id.clone(),
                    },
                    tx,
                )
                .await?;
            self.hooks
                .before_session_creation(
                    &mut BeforeSessionCreation {
                        user_id: user.id.clone(),
                        user_agent: self.user_agent.clone(),
                        ip_address: self.ip_address.clone(),
                    },
                    tx,
                )
                .await?;
            let session = Session::builder()
                .token(SessionToken::new_random())
                .user_id(user.id.clone())
                .user_agent(self.user_agent)
                .ip_address(self.ip_address)
                .expires_at(chrono::Utc::now() + self.expires_in)
                .build()
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let session = self
                .session_repository
                .create(tx, session)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_session_creation(
                    &AfterSessionCreation {
                        user_id: user.id.clone(),
                        session: session.clone(),
                    },
                    tx,
                )
                .await?;
            Ok((user, session))
        })
    }
}

impl<U: UserRepository + 'static, P: torii_core::repositories::PasskeyRepository + 'static>
    TransactionOperation<Option<User>> for AuthenticatePasskeyOperation<U, P>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<User>, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let credential = self
                .repository
                .get_credential(&self.credential_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let Some(credential) = credential else {
                return Ok(None);
            };
            self.repository
                .update_last_used(tx, &self.credential_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let user = self
                .user_repository
                .find_by_id(&credential.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_passkey_authentication(
                    &AfterPasskeyAuthentication {
                        user_id: credential.user_id,
                    },
                    tx,
                )
                .await?;
            Ok(user)
        })
    }
}
impl<P: torii_core::repositories::PasskeyRepository + 'static> TransactionOperation<()>
    for RemoveUserPasskeysOperation<P>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.repository
                .delete_all_for_user(tx, &self.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_passkey_removal(
                    &AfterPasskeyRemoval {
                        user_id: self.user_id,
                    },
                    tx,
                )
                .await?;
            Ok(())
        })
    }
}

pub struct AuthenticateOAuthOperation<U, O, R> {
    pub user_repository: Arc<U>,
    pub oauth_repository: Arc<O>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub provider: String,
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
}

pub struct CompleteOAuthAuthenticationOperation<U, O, S, R> {
    pub user_repository: Arc<U>,
    pub oauth_repository: Arc<O>,
    pub session_repository: Arc<S>,
    pub repositories: Arc<R>,
    pub hooks: Arc<HookRegistry>,
    pub provider: String,
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub expires_in: chrono::Duration,
}

impl<
    U: UserRepository + 'static,
    O: torii_core::repositories::OAuthRepository + 'static,
    S: SessionRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
> TransactionOperation<(OAuthAuthenticationResult, Session)>
    for CompleteOAuthAuthenticationOperation<U, O, S, R>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(OAuthAuthenticationResult, Session), TransactionError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let result = Box::new(AuthenticateOAuthOperation {
                user_repository: self.user_repository,
                oauth_repository: self.oauth_repository,
                repositories: self.repositories.clone(),
                hooks: self.hooks.clone(),
                provider: self.provider,
                subject: self.subject,
                email: self.email,
                name: self.name,
            })
            .execute(tx)
            .await?;
            self.hooks
                .before_session_creation(
                    &mut BeforeSessionCreation {
                        user_id: result.user.id.clone(),
                        user_agent: self.user_agent.clone(),
                        ip_address: self.ip_address.clone(),
                    },
                    tx,
                )
                .await?;
            let session = Session::builder()
                .token(SessionToken::new_random())
                .user_id(result.user.id.clone())
                .user_agent(self.user_agent)
                .ip_address(self.ip_address)
                .expires_at(chrono::Utc::now() + self.expires_in)
                .build()
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            let session = self
                .session_repository
                .create(tx, session)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_session_creation(
                    &AfterSessionCreation {
                        user_id: result.user.id.clone(),
                        session: session.clone(),
                    },
                    tx,
                )
                .await?;
            Ok((result, session))
        })
    }
}

pub struct OAuthAuthenticationResult {
    pub user: User,
    pub user_created: bool,
    pub account_linked: bool,
}

impl<U, O, R> TransactionOperation<OAuthAuthenticationResult>
    for AuthenticateOAuthOperation<U, O, R>
where
    U: UserRepository + 'static,
    O: torii_core::repositories::OAuthRepository + 'static,
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<OAuthAuthenticationResult, TransactionError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let mut context = BeforeOAuthAuthentication {
                email: self.email.clone(),
                provider: self.provider.clone(),
            };
            self.hooks
                .before_oauth_authentication(&mut context, tx)
                .await?;
            if let Some(user) = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .oauth()
                    .find_user_by_provider(&self.provider, &self.subject)
                    .await
            }
            .map_err(|e| TransactionError::Failed(e.to_string()))?
            {
                self.hooks
                    .after_oauth_authentication(
                        &AfterOAuthAuthentication {
                            user_id: user.id.clone(),
                            provider: self.provider,
                        },
                        tx,
                    )
                    .await?;
                return Ok(OAuthAuthenticationResult {
                    user,
                    user_created: false,
                    account_linked: false,
                });
            }
            if let Some(user) = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories.users().find_by_email(&context.email).await
            }
            .map_err(|e| TransactionError::Failed(e.to_string()))?
            {
                self.oauth_repository
                    .link_account(tx, &user.id, &self.provider, &self.subject)
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                self.hooks
                    .after_oauth_authentication(
                        &AfterOAuthAuthentication {
                            user_id: user.id.clone(),
                            provider: self.provider,
                        },
                        tx,
                    )
                    .await?;
                return Ok(OAuthAuthenticationResult {
                    user,
                    user_created: false,
                    account_linked: true,
                });
            }
            let mut registration = BeforeUserRegistration {
                email: context.email.clone(),
                name: self.name.clone(),
            };
            self.hooks
                .before_user_registration(&mut registration, tx)
                .await?;
            let mut builder = NewUser::builder()
                .id(UserId::new_random())
                .email(registration.email);
            if let Some(name) = registration.name {
                builder = builder.name(name);
            }
            let user = {
                let mut repositories = self
                    .repositories
                    .transactional(tx)
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                repositories
                    .users()
                    .create(
                        builder
                            .build()
                            .map_err(|e| TransactionError::Failed(e.to_string()))?,
                    )
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?
            };
            self.hooks
                .after_user_registration(&AfterUserRegistration { user: user.clone() }, tx)
                .await?;
            self.oauth_repository
                .create_account(tx, &self.provider, &self.subject, &user.id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_oauth_authentication(
                    &AfterOAuthAuthentication {
                        user_id: user.id.clone(),
                        provider: self.provider,
                    },
                    tx,
                )
                .await?;
            Ok(OAuthAuthenticationResult {
                user,
                user_created: true,
                account_linked: false,
            })
        })
    }
}

impl<O: torii_core::repositories::OAuthRepository + 'static> TransactionOperation<()>
    for UnlinkOAuthAccountOperation<O>
{
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.hooks
                .before_oauth_account_unlink(
                    &mut BeforeOAuthAccountUnlink {
                        user_id: self.user_id.clone(),
                        provider: self.provider.clone(),
                    },
                    tx,
                )
                .await?;
            self.repository
                .unlink_account(tx, &self.user_id, &self.provider)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_oauth_account_unlink(
                    &AfterOAuthAccountUnlink {
                        user_id: self.user_id,
                        provider: self.provider,
                    },
                    tx,
                )
                .await?;
            Ok(())
        })
    }
}

impl<U: UserRepository + 'static> TransactionOperation<()> for VerifyEmailOperation<U> {
    fn execute<'a>(
        self: Box<Self>,
        tx: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.hooks
                .before_email_verification_request(
                    &mut BeforeEmailVerificationRequest {
                        user_id: self.user_id.clone(),
                    },
                    tx,
                )
                .await?;
            self.user_repository
                .mark_email_verified(tx, &self.user_id)
                .await
                .map_err(|e| TransactionError::Failed(e.to_string()))?;
            self.hooks
                .after_email_verification(
                    &AfterEmailVerification {
                        user_id: self.user_id,
                    },
                    tx,
                )
                .await?;
            Ok(())
        })
    }
}

impl<R> TransactionOperation<User> for RegisterUserOperation<R>
where
    R: torii_core::repositories::TransactionalRepositoryProvider + 'static,
{
    fn execute<'a>(
        self: Box<Self>,
        transaction: &'a mut dyn TransactionAdapter,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<User, TransactionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut context = BeforeUserRegistration {
                email: self.new_user.email.clone(),
                name: self.new_user.name.clone(),
            };
            self.hooks
                .before_user_registration(&mut context, transaction)
                .await?;
            let mut new_user = self.new_user;
            new_user.email = context.email;
            new_user.name = context.name;
            let user = {
                let mut repositories = self
                    .repositories
                    .transactional(transaction)
                    .map_err(|error| TransactionError::Failed(error.to_string()))?;
                let user = repositories
                    .users()
                    .create(new_user)
                    .await
                    .map_err(|error| TransactionError::Failed(error.to_string()))?;
                repositories
                    .passwords()
                    .set_password_hash(&user.id, &self.password_hash)
                    .await
                    .map_err(|error| TransactionError::Failed(error.to_string()))?;
                user
            };
            self.hooks
                .after_user_registration(&AfterUserRegistration { user: user.clone() }, transaction)
                .await?;
            Ok(user)
        })
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Ordered, builder-configured hook registry.
#[derive(Clone, Default)]
pub struct HookRegistry {
    hooks: Arc<RwLock<Vec<Arc<dyn ToriiHook>>>>,
}

/// Internal helper: run before-hooks and return `Err(Rejected)` on first rejection.
macro_rules! run_before_hooks {
    ($self:ident, $method:ident, $context:ident, $transaction:ident) => {{
        let hooks = $self
            .hooks
            .read()
            .expect("hook registry lock poisoned")
            .clone();
        for hook in hooks {
            if let HookDecision::Reject { code, message } =
                hook.$method($context, $transaction).await?
            {
                return Err(HookError::Rejected { code, message });
            }
        }
        Ok(())
    }};
}

/// Internal helper: run after-hooks sequentially.
macro_rules! run_after_hooks {
    ($self:ident, $method:ident, $context:ident, $transaction:ident) => {{
        let hooks = $self
            .hooks
            .read()
            .expect("hook registry lock poisoned")
            .clone();
        for hook in hooks {
            hook.$method($context, $transaction).await?;
        }
        Ok(())
    }};
}

impl HookRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hook. Hooks execute in registration order.
    pub async fn register(&self, hook: Arc<dyn ToriiHook>) {
        self.register_sync(hook);
    }

    /// Register a hook synchronously during builder construction.
    pub fn register_sync(&self, hook: Arc<dyn ToriiHook>) {
        self.hooks
            .write()
            .expect("hook registry lock poisoned")
            .push(hook);
    }

    // -- user lifecycle --

    pub async fn before_user_registration(
        &self,
        context: &mut BeforeUserRegistration,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_user_registration, context, transaction)
    }

    pub async fn after_user_registration(
        &self,
        context: &AfterUserRegistration,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_user_registration, context, transaction)
    }

    pub async fn before_user_update(
        &self,
        context: &mut BeforeUserUpdate,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_user_update, context, transaction)
    }

    pub async fn after_user_update(
        &self,
        context: &AfterUserUpdate,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_user_update, context, transaction)
    }

    pub async fn before_user_deletion(
        &self,
        context: &mut BeforeUserDeletion,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_user_deletion, context, transaction)
    }

    pub async fn after_user_deletion(
        &self,
        context: &AfterUserDeletion,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_user_deletion, context, transaction)
    }

    // -- session lifecycle --

    pub async fn before_session_creation(
        &self,
        context: &mut BeforeSessionCreation,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_session_creation, context, transaction)
    }

    pub async fn after_session_creation(
        &self,
        context: &AfterSessionCreation,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_session_creation, context, transaction)
    }

    pub async fn before_session_deletion(
        &self,
        context: &mut BeforeSessionDeletion,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_session_deletion, context, transaction)
    }

    pub async fn after_session_deletion(
        &self,
        context: &AfterSessionDeletion,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_session_deletion, context, transaction)
    }

    pub async fn before_sessions_clear(
        &self,
        context: &mut BeforeSessionsClear,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_sessions_clear, context, transaction)
    }

    pub async fn after_sessions_clear(
        &self,
        context: &AfterSessionsClear,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_sessions_clear, context, transaction)
    }

    pub async fn after_session_refresh(
        &self,
        context: &AfterSessionRefresh,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_session_refresh, context, transaction)
    }

    // -- password authentication --

    pub async fn before_password_registration(
        &self,
        context: &mut BeforePasswordRegistration,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_password_registration, context, transaction)
    }

    pub async fn after_password_registration(
        &self,
        context: &AfterPasswordRegistration,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_password_registration, context, transaction)
    }

    pub async fn before_password_authentication(
        &self,
        context: &mut BeforePasswordAuthentication,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_password_authentication, context, transaction)
    }

    pub async fn after_password_authentication(
        &self,
        context: &AfterPasswordAuthentication,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_password_authentication, context, transaction)
    }

    pub async fn before_password_change(
        &self,
        context: &mut BeforePasswordChange,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_password_change, context, transaction)
    }

    pub async fn after_password_change(
        &self,
        context: &AfterPasswordChange,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_password_change, context, transaction)
    }

    pub async fn after_password_removal(
        &self,
        context: &AfterPasswordRemoval,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_password_removal, context, transaction)
    }

    // -- password reset --

    pub async fn before_password_reset_request(
        &self,
        context: &mut BeforePasswordResetRequest,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_password_reset_request, context, transaction)
    }

    pub async fn after_password_reset_request(
        &self,
        context: &AfterPasswordResetRequest,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_password_reset_request, context, transaction)
    }

    pub async fn after_password_reset_completion(
        &self,
        context: &AfterPasswordResetCompletion,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_password_reset_completion, context, transaction)
    }

    // -- OAuth --

    pub async fn before_oauth_authentication(
        &self,
        context: &mut BeforeOAuthAuthentication,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_oauth_authentication, context, transaction)
    }

    pub async fn after_oauth_authentication(
        &self,
        context: &AfterOAuthAuthentication,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_oauth_authentication, context, transaction)
    }

    pub async fn before_oauth_account_link(
        &self,
        context: &mut BeforeOAuthAccountLink,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_oauth_account_link, context, transaction)
    }

    pub async fn after_oauth_account_link(
        &self,
        context: &AfterOAuthAccountLink,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_oauth_account_link, context, transaction)
    }

    pub async fn before_oauth_account_unlink(
        &self,
        context: &mut BeforeOAuthAccountUnlink,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_oauth_account_unlink, context, transaction)
    }

    pub async fn after_oauth_account_unlink(
        &self,
        context: &AfterOAuthAccountUnlink,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_oauth_account_unlink, context, transaction)
    }

    // -- passkeys --

    pub async fn before_passkey_registration(
        &self,
        context: &mut BeforePasskeyRegistration,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_passkey_registration, context, transaction)
    }

    pub async fn after_passkey_registration(
        &self,
        context: &AfterPasskeyRegistration,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_passkey_registration, context, transaction)
    }

    pub async fn after_passkey_authentication(
        &self,
        context: &AfterPasskeyAuthentication,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_passkey_authentication, context, transaction)
    }

    pub async fn after_passkey_removal(
        &self,
        context: &AfterPasskeyRemoval,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_passkey_removal, context, transaction)
    }

    // -- magic links --

    pub async fn before_magic_link_send(
        &self,
        context: &mut BeforeMagicLinkSend,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_magic_link_send, context, transaction)
    }

    pub async fn after_magic_link_authentication(
        &self,
        context: &AfterMagicLinkAuthentication,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_magic_link_authentication, context, transaction)
    }

    // -- email verification --

    pub async fn before_email_verification_request(
        &self,
        context: &mut BeforeEmailVerificationRequest,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(
            self,
            before_email_verification_request,
            context,
            transaction
        )
    }

    pub async fn after_email_verification(
        &self,
        context: &AfterEmailVerification,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_email_verification, context, transaction)
    }

    // -- brute force / security --

    pub async fn before_brute_force_check(
        &self,
        context: &mut BeforeBruteForceCheck,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_brute_force_check, context, transaction)
    }

    pub async fn after_brute_force_check(
        &self,
        context: &AfterBruteForceCheck,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_brute_force_check, context, transaction)
    }

    pub async fn before_brute_force_record(
        &self,
        context: &mut BeforeBruteForceRecord,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_brute_force_record, context, transaction)
    }

    pub async fn after_brute_force_record(
        &self,
        context: &AfterBruteForceRecord,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_brute_force_record, context, transaction)
    }

    pub async fn before_brute_force_reset(
        &self,
        context: &mut BeforeBruteForceReset,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_before_hooks!(self, before_brute_force_reset, context, transaction)
    }

    pub async fn after_brute_force_reset(
        &self,
        context: &AfterBruteForceReset,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_brute_force_reset, context, transaction)
    }

    pub async fn after_login_failure(
        &self,
        context: &AfterLoginFailure,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_login_failure, context, transaction)
    }

    pub async fn after_account_lockout(
        &self,
        context: &AfterAccountLockout,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_account_lockout, context, transaction)
    }

    pub async fn after_account_unlock(
        &self,
        context: &AfterAccountUnlock,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        run_after_hooks!(self, after_account_unlock, context, transaction)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use torii_core::TransactionRunner;

    struct NoopTransaction;

    #[async_trait]
    impl TransactionAdapter for NoopTransaction {
        fn backend(&self) -> &'static str {
            "sqlite"
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    struct CountingHook {
        calls: Arc<AtomicUsize>,
        decision: HookDecision,
    }

    struct FailingAfterHook;

    #[async_trait]
    impl ToriiHook for FailingAfterHook {
        async fn after_user_registration(
            &self,
            _context: &AfterUserRegistration,
            _transaction: &mut dyn TransactionAdapter,
        ) -> Result<(), HookError> {
            Err(HookError::Failed("after-hook failed".into()))
        }
    }

    struct ProbeOperation(Arc<AtomicUsize>);

    impl TransactionOperation<usize> for ProbeOperation {
        fn execute<'a>(
            self: Box<Self>,
            _tx: &'a mut dyn TransactionAdapter,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<usize, TransactionError>> + Send + 'a>,
        > {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            })
        }
    }

    struct RecordingRunner;

    #[async_trait]
    impl TransactionRunner for RecordingRunner {
        async fn run<T: Send + 'static>(
            &self,
            operation: Box<dyn TransactionOperation<T>>,
        ) -> Result<T, TransactionError> {
            let mut transaction = NoopTransaction;
            operation.execute(&mut transaction).await
        }
    }

    #[async_trait]
    impl ToriiHook for CountingHook {
        async fn before_user_registration(
            &self,
            _ctx: &mut BeforeUserRegistration,
            _tx: &mut dyn TransactionAdapter,
        ) -> Result<HookDecision, HookError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }
    }

    #[tokio::test]
    async fn registry_runs_hooks_in_registration_order_until_rejection() {
        let registry = HookRegistry::new();
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        registry
            .register(Arc::new(CountingHook {
                calls: first.clone(),
                decision: HookDecision::Continue,
            }))
            .await;
        registry
            .register(Arc::new(CountingHook {
                calls: second.clone(),
                decision: HookDecision::Reject {
                    code: "blocked".into(),
                    message: "blocked by policy".into(),
                },
            }))
            .await;

        let mut context = BeforeUserRegistration {
            email: "user@example.com".into(),
            name: None,
        };
        let mut transaction = NoopTransaction;
        let result = registry
            .before_user_registration(&mut context, &mut transaction)
            .await;

        assert!(matches!(result, Err(HookError::Rejected { .. })));
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn registry_continues_when_all_hooks_allow() {
        let registry = HookRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        registry
            .register(Arc::new(CountingHook {
                calls: calls.clone(),
                decision: HookDecision::Continue,
            }))
            .await;
        registry
            .register(Arc::new(CountingHook {
                calls: calls.clone(),
                decision: HookDecision::Continue,
            }))
            .await;

        let mut context = BeforeUserRegistration {
            email: "user@example.com".into(),
            name: None,
        };
        let mut transaction = NoopTransaction;
        let result = registry
            .before_user_registration(&mut context, &mut transaction)
            .await;

        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn after_hook_failure_is_returned() {
        let registry = HookRegistry::new();
        registry.register(Arc::new(FailingAfterHook)).await;
        let mut transaction = NoopTransaction;
        let result = registry
            .after_user_registration(
                &AfterUserRegistration {
                    user: User::builder()
                        .id(UserId::new("user-1"))
                        .email("user@example.com".to_string())
                        .build()
                        .unwrap(),
                },
                &mut transaction,
            )
            .await;

        assert!(
            matches!(result, Err(HookError::Failed(message)) if message == "after-hook failed")
        );
    }

    #[tokio::test]
    async fn empty_registry_is_noop() {
        let registry = HookRegistry::new();
        let mut context = BeforeUserRegistration {
            email: "user@example.com".into(),
            name: None,
        };
        let mut transaction = NoopTransaction;
        assert!(
            registry
                .before_user_registration(&mut context, &mut transaction)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn transaction_runner_executes_operation_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let result = RecordingRunner
            .run(Box::new(ProbeOperation(calls.clone())))
            .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn first_rejection_stops_subsequent_hooks() {
        let registry = HookRegistry::new();
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        registry
            .register(Arc::new(CountingHook {
                calls: first.clone(),
                decision: HookDecision::Reject {
                    code: "first".into(),
                    message: "first rejects".into(),
                },
            }))
            .await;
        registry
            .register(Arc::new(CountingHook {
                calls: second.clone(),
                decision: HookDecision::Continue,
            }))
            .await;

        let mut context = BeforeUserRegistration {
            email: "user@example.com".into(),
            name: None,
        };
        let mut transaction = NoopTransaction;
        let result = registry
            .before_user_registration(&mut context, &mut transaction)
            .await;

        assert!(matches!(result, Err(HookError::Rejected { .. })));
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 0);
    }
}
