//! Repository families bound to one active backend transaction.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use crate::{
    Error, FailedLoginAttempt, NewUser, OAuthAccount, Session, User, UserId,
    repositories::{PasskeyCredential, RepositoryProvider},
    session::SessionToken,
    storage::{AttemptStats, SecureToken, TokenPurpose},
    transaction::TransactionAdapter,
};

/// A view over repositories that all use the same transaction.
pub trait TransactionRepositoryView {
    type Users<'a>: TransactionUserRepository + Send
    where
        Self: 'a;
    type Passwords<'a>: TransactionPasswordRepository + Send
    where
        Self: 'a;
    type BruteForce<'a>: TransactionBruteForceRepository + Send
    where
        Self: 'a;
    type Sessions<'a>: TransactionSessionRepository + Send
    where
        Self: 'a;
    type Tokens<'a>: TransactionTokenRepository + Send
    where
        Self: 'a;
    type OAuth<'a>: TransactionOAuthRepository + Send
    where
        Self: 'a;
    type Passkeys<'a>: TransactionPasskeyRepository + Send
    where
        Self: 'a;

    fn users(&mut self) -> Self::Users<'_>;
    fn passwords(&mut self) -> Self::Passwords<'_>;
    fn brute_force(&mut self) -> Self::BruteForce<'_>;
    fn sessions(&mut self) -> Self::Sessions<'_>;
    fn tokens(&mut self) -> Self::Tokens<'_>;
    fn oauth(&mut self) -> Self::OAuth<'_>;
    fn passkeys(&mut self) -> Self::Passkeys<'_>;
}

/// Creates a transaction view with a backend-specific GAT.
pub trait TransactionalRepositoryProvider: RepositoryProvider + Sized {
    type Transaction<'a>: TransactionRepositoryView + Send
    where
        Self: 'a;

    fn transaction<'a>(
        &'a self,
        transaction: &'a mut dyn TransactionAdapter,
    ) -> Result<Self::Transaction<'a>, Error>;

    fn transactional<'a>(
        &'a self,
        transaction: &'a mut dyn TransactionAdapter,
    ) -> Result<Self::Transaction<'a>, Error> {
        self.transaction(transaction)
    }
}

#[async_trait]
pub trait TransactionUserRepository {
    async fn create(&mut self, user: NewUser) -> Result<User, Error>;
    async fn find_by_id(&mut self, id: &UserId) -> Result<Option<User>, Error>;
    async fn find_by_email(&mut self, email: &str) -> Result<Option<User>, Error>;
    async fn delete(&mut self, id: &UserId) -> Result<(), Error>;
}

#[async_trait]
pub trait TransactionPasswordRepository {
    async fn set_password_hash(&mut self, user_id: &UserId, hash: &str) -> Result<(), Error>;
    async fn get_password_hash(&mut self, user_id: &UserId) -> Result<Option<String>, Error>;
}

#[async_trait]
pub trait TransactionBruteForceRepository {
    async fn record_failed_attempt(
        &mut self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error>;
    async fn get_attempt_stats(
        &mut self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error>;
    async fn clear_attempts(&mut self, email: &str) -> Result<u64, Error>;
    async fn set_locked_at(
        &mut self,
        email: &str,
        locked_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error>;
    async fn get_locked_at(&mut self, email: &str) -> Result<Option<DateTime<Utc>>, Error>;
}

#[async_trait]
pub trait TransactionSessionRepository {
    async fn create(&mut self, session: Session) -> Result<Session, Error>;
    async fn find_by_token(&mut self, token: &SessionToken) -> Result<Option<Session>, Error>;
    async fn find_by_user_id(&mut self, user_id: &UserId) -> Result<Vec<Session>, Error>;
    async fn delete(&mut self, token: &SessionToken) -> Result<(), Error>;
    async fn delete_by_user_id(&mut self, user_id: &UserId) -> Result<(), Error>;
    async fn refresh(&mut self, token: &SessionToken, duration: Duration)
    -> Result<Session, Error>;
}

#[async_trait]
pub trait TransactionTokenRepository {
    async fn create_token(
        &mut self,
        user_id: &UserId,
        purpose: TokenPurpose,
        expires_in: Duration,
    ) -> Result<SecureToken, Error>;
    async fn verify_token(
        &mut self,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error>;
    async fn check_token(&mut self, token: &str, purpose: TokenPurpose) -> Result<bool, Error>;
}

#[async_trait]
pub trait TransactionOAuthRepository {
    async fn create_account(
        &mut self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error>;
    async fn find_user_by_provider(
        &mut self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error>;
    async fn find_account_by_provider(
        &mut self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error>;
    async fn find_accounts_by_user_id(
        &mut self,
        user_id: &UserId,
    ) -> Result<Vec<OAuthAccount>, Error>;
    async fn link_account(
        &mut self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error>;
    async fn unlink_account(&mut self, user_id: &UserId, provider: &str) -> Result<(), Error>;
    async fn store_pkce_verifier(
        &mut self,
        state: &str,
        verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error>;
    async fn get_pkce_verifier(&mut self, state: &str) -> Result<Option<String>, Error>;
    async fn delete_pkce_verifier(&mut self, state: &str) -> Result<(), Error>;
}

#[async_trait]
pub trait TransactionPasskeyRepository {
    async fn add_credential(
        &mut self,
        user_id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        name: Option<String>,
    ) -> Result<PasskeyCredential, Error>;
    async fn get_credentials_for_user(
        &mut self,
        user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential>, Error>;
    async fn get_credential(
        &mut self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, Error>;
    async fn update_last_used(&mut self, credential_id: &[u8]) -> Result<(), Error>;
    async fn delete_credential(&mut self, credential_id: &[u8]) -> Result<(), Error>;
    async fn delete_all_for_user(&mut self, user_id: &UserId) -> Result<(), Error>;
}
