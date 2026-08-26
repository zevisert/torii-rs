use async_trait::async_trait;
use base64::prelude::*;
use chrono::{DateTime, Duration, Utc};
use rand::{TryRngCore, rngs::OsRng};
use sqlx::{PgConnection, Postgres, Transaction};
use std::str::FromStr;
use torii_core::{
    Error, FailedLoginAttempt, NewUser, OAuthAccount, Session, User, UserId,
    error::StorageError,
    repositories::{
        PasskeyCredential, TransactionBruteForceRepository, TransactionOAuthRepository,
        TransactionPasskeyRepository, TransactionPasswordRepository, TransactionRepositoryView,
        TransactionSessionRepository, TransactionTokenRepository, TransactionUserRepository,
        TransactionalRepositoryProvider,
    },
    session::SessionToken,
    storage::{AttemptStats, SecureToken, TokenPurpose},
    transaction::TransactionAdapter,
};

use crate::oauth::PostgresOAuthAccount;
use crate::repositories::PostgresRepositoryProvider;
use crate::{PostgresTransactionAdapter, PostgresUser};

fn mismatch() -> Error {
    Error::Storage(StorageError::Database(
        "PostgreSQL transaction adapter required".into(),
    ))
}

fn connection<'a>(transaction: &'a mut Transaction<'static, Postgres>) -> &'a mut PgConnection {
    transaction
}

pub struct PostgresTransactionView<'a> {
    pub(crate) transaction: &'a mut Transaction<'static, Postgres>,
}

impl TransactionRepositoryView for PostgresTransactionView<'_> {
    type Users<'a>
        = PostgresTransactionUsers<'a>
    where
        Self: 'a;
    type Passwords<'a>
        = PostgresTransactionPasswords<'a>
    where
        Self: 'a;
    type BruteForce<'a>
        = PostgresTransactionBruteForce<'a>
    where
        Self: 'a;
    type Sessions<'a>
        = PostgresTransactionSessions<'a>
    where
        Self: 'a;
    type Tokens<'a>
        = PostgresTransactionTokens<'a>
    where
        Self: 'a;
    type OAuth<'a>
        = PostgresTransactionOAuth<'a>
    where
        Self: 'a;
    type Passkeys<'a>
        = PostgresTransactionPasskeys<'a>
    where
        Self: 'a;

    fn users(&mut self) -> Self::Users<'_> {
        PostgresTransactionUsers {
            transaction: &mut *self.transaction,
        }
    }
    fn passwords(&mut self) -> Self::Passwords<'_> {
        PostgresTransactionPasswords {
            transaction: &mut *self.transaction,
        }
    }
    fn brute_force(&mut self) -> Self::BruteForce<'_> {
        PostgresTransactionBruteForce {
            transaction: &mut *self.transaction,
        }
    }
    fn sessions(&mut self) -> Self::Sessions<'_> {
        PostgresTransactionSessions {
            transaction: &mut *self.transaction,
        }
    }
    fn tokens(&mut self) -> Self::Tokens<'_> {
        PostgresTransactionTokens {
            transaction: &mut *self.transaction,
        }
    }
    fn oauth(&mut self) -> Self::OAuth<'_> {
        PostgresTransactionOAuth {
            transaction: &mut *self.transaction,
        }
    }
    fn passkeys(&mut self) -> Self::Passkeys<'_> {
        PostgresTransactionPasskeys {
            transaction: &mut *self.transaction,
        }
    }
}

macro_rules! family {
    ($name:ident) => {
        pub struct $name<'a> {
            transaction: &'a mut Transaction<'static, Postgres>,
        }
    };
}
family!(PostgresTransactionUsers);
family!(PostgresTransactionPasswords);
family!(PostgresTransactionBruteForce);
family!(PostgresTransactionSessions);
family!(PostgresTransactionTokens);
family!(PostgresTransactionOAuth);
family!(PostgresTransactionPasskeys);

fn db(error: impl ToString) -> Error {
    Error::Storage(StorageError::Database(error.to_string()))
}

#[async_trait]
impl TransactionUserRepository for PostgresTransactionUsers<'_> {
    async fn create(&mut self, user: NewUser) -> Result<User, Error> {
        sqlx::query_as::<_, PostgresUser>("INSERT INTO users (id, email, name, email_verified_at) VALUES ($1, $2, $3, $4) RETURNING id, email, name, email_verified_at, locked_at, created_at, updated_at")
            .bind(user.id.as_str()).bind(user.email).bind(user.name).bind(user.email_verified_at)
            .fetch_one(connection(self.transaction)).await.map(Into::into).map_err(db)
    }
    async fn find_by_id(&mut self, id: &UserId) -> Result<Option<User>, Error> {
        sqlx::query_as::<_, PostgresUser>("SELECT id, email, name, email_verified_at, locked_at, created_at, updated_at FROM users WHERE id = $1")
            .bind(id.as_str()).fetch_optional(connection(self.transaction)).await.map(|v| v.map(Into::into)).map_err(db)
    }
    async fn find_by_email(&mut self, email: &str) -> Result<Option<User>, Error> {
        sqlx::query_as::<_, PostgresUser>("SELECT id, email, name, email_verified_at, locked_at, created_at, updated_at FROM users WHERE email = $1")
            .bind(email).fetch_optional(connection(self.transaction)).await.map(|v| v.map(Into::into)).map_err(db)
    }
    async fn delete(&mut self, id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id.as_str())
            .execute(connection(self.transaction))
            .await
            .map(|_| ())
            .map_err(db)
    }
}

#[async_trait]
impl TransactionPasswordRepository for PostgresTransactionPasswords<'_> {
    async fn set_password_hash(&mut self, id: &UserId, hash: &str) -> Result<(), Error> {
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(hash)
            .bind(id.as_str())
            .execute(connection(self.transaction))
            .await
            .map(|_| ())
            .map_err(db)
    }
    async fn get_password_hash(&mut self, id: &UserId) -> Result<Option<String>, Error> {
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(id.as_str())
            .fetch_optional(connection(self.transaction))
            .await
            .map_err(db)
    }
}

#[derive(sqlx::FromRow)]
struct AttemptRow {
    count: i64,
    latest_at: Option<DateTime<Utc>>,
}

#[async_trait]
impl TransactionBruteForceRepository for PostgresTransactionBruteForce<'_> {
    async fn record_failed_attempt(
        &mut self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: i64,
            email: String,
            ip_address: Option<String>,
            attempted_at: DateTime<Utc>,
        }
        sqlx::query_as::<_, Row>("INSERT INTO failed_login_attempts (email, ip_address, attempted_at) VALUES ($1, $2, NOW()) RETURNING id, email, ip_address, attempted_at")
            .bind(email).bind(ip_address).fetch_one(connection(self.transaction)).await.map(|r| FailedLoginAttempt { id: r.id, email: r.email, ip_address: r.ip_address, attempted_at: r.attempted_at }).map_err(db)
    }
    async fn get_attempt_stats(
        &mut self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error> {
        let row = sqlx::query_as::<_, AttemptRow>("SELECT COUNT(*) as count, MAX(attempted_at) as latest_at FROM failed_login_attempts WHERE email = $1 AND attempted_at >= $2")
            .bind(email).bind(since).fetch_one(connection(self.transaction)).await.map_err(db)?;
        Ok(AttemptStats {
            count: row.count as u32,
            latest_at: row.latest_at,
        })
    }
    async fn clear_attempts(&mut self, email: &str) -> Result<u64, Error> {
        Ok(
            sqlx::query("DELETE FROM failed_login_attempts WHERE email = $1")
                .bind(email)
                .execute(connection(self.transaction))
                .await
                .map_err(db)?
                .rows_affected(),
        )
    }
    async fn set_locked_at(
        &mut self,
        email: &str,
        locked_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        sqlx::query("UPDATE users SET locked_at = $1 WHERE email = $2")
            .bind(locked_at)
            .bind(email)
            .execute(connection(self.transaction))
            .await
            .map(|_| ())
            .map_err(db)
    }
    async fn get_locked_at(&mut self, email: &str) -> Result<Option<DateTime<Utc>>, Error> {
        sqlx::query_as::<_, (Option<DateTime<Utc>>,)>(
            "SELECT locked_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(connection(self.transaction))
        .await
        .map(|v| v.and_then(|r| r.0))
        .map_err(db)
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    token: String,
    user_id: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

fn session(row: SessionRow, token: &SessionToken) -> Option<Session> {
    token.verify_hash(&row.token).then_some(Session {
        token: Some(token.clone()),
        token_hash: row.token,
        user_id: UserId::new(&row.user_id),
        user_agent: row.user_agent,
        ip_address: row.ip_address,
        created_at: row.created_at,
        updated_at: row.updated_at,
        expires_at: row.expires_at,
    })
}

#[async_trait]
impl TransactionSessionRepository for PostgresTransactionSessions<'_> {
    async fn create(&mut self, session: Session) -> Result<Session, Error> {
        sqlx::query("INSERT INTO sessions (token, user_id, user_agent, ip_address, created_at, updated_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)").bind(&session.token_hash).bind(session.user_id.as_str()).bind(&session.user_agent).bind(&session.ip_address).bind(session.created_at).bind(session.updated_at).bind(session.expires_at).execute(connection(self.transaction)).await.map(|_| session).map_err(db)
    }
    async fn find_by_token(&mut self, token: &SessionToken) -> Result<Option<Session>, Error> {
        sqlx::query_as::<_, SessionRow>("SELECT token, user_id, user_agent, ip_address, created_at, updated_at, expires_at FROM sessions WHERE token = $1").bind(token.token_hash()).fetch_optional(connection(self.transaction)).await.map(|v| v.and_then(|r| session(r, token))).map_err(db)
    }
    async fn find_by_user_id(&mut self, id: &UserId) -> Result<Vec<Session>, Error> {
        let rows = sqlx::query_as::<_, SessionRow>("SELECT token, user_id, user_agent, ip_address, created_at, updated_at, expires_at FROM sessions WHERE user_id = $1 ORDER BY created_at DESC").bind(id.as_str()).fetch_all(connection(self.transaction)).await.map_err(db)?;
        Ok(rows
            .into_iter()
            .map(|r| Session {
                token: None,
                token_hash: r.token,
                user_id: UserId::new(&r.user_id),
                user_agent: r.user_agent,
                ip_address: r.ip_address,
                created_at: r.created_at,
                updated_at: r.updated_at,
                expires_at: r.expires_at,
            })
            .collect())
    }
    async fn delete(&mut self, token: &SessionToken) -> Result<(), Error> {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token.token_hash())
            .execute(connection(self.transaction))
            .await
            .map(|_| ())
            .map_err(db)
    }
    async fn delete_by_user_id(&mut self, id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id.as_str())
            .execute(connection(self.transaction))
            .await
            .map(|_| ())
            .map_err(db)
    }
    async fn refresh(
        &mut self,
        token: &SessionToken,
        duration: Duration,
    ) -> Result<Session, Error> {
        let now = Utc::now();
        sqlx::query("UPDATE sessions SET expires_at = $1, updated_at = $2 WHERE token = $3")
            .bind(now + duration)
            .bind(now)
            .bind(token.token_hash())
            .execute(connection(self.transaction))
            .await
            .map_err(db)?;
        self.find_by_token(token)
            .await?
            .ok_or_else(|| db("Session not found"))
    }
}

fn token_string() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("system RNG unavailable");
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

#[async_trait]
impl TransactionTokenRepository for PostgresTransactionTokens<'_> {
    async fn create_token(
        &mut self,
        user_id: &UserId,
        purpose: TokenPurpose,
        expires_in: Duration,
    ) -> Result<SecureToken, Error> {
        let token = token_string();
        let hash = torii_core::crypto::hash_token(&token);
        let now = Utc::now();
        let expires_at = now + expires_in;
        let value = SecureToken::new(
            user_id.clone(),
            token,
            hash,
            purpose,
            None,
            expires_at,
            now,
            now,
        );
        sqlx::query("INSERT INTO secure_tokens (user_id, token, purpose, used_at, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)").bind(value.user_id.as_str()).bind(&value.token_hash).bind(value.purpose.as_str()).bind(value.used_at).bind(value.expires_at).bind(value.created_at).bind(value.updated_at).execute(connection(self.transaction)).await.map(|_| value).map_err(db)
    }
    async fn verify_token(
        &mut self,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        let hash = torii_core::crypto::hash_token(token);
        let now = Utc::now();
        let row = sqlx::query_as::<_, crate::repositories::token::SecureTokenRow>("SELECT user_id, token, purpose, used_at, expires_at, created_at, updated_at FROM secure_tokens WHERE token = $1 AND purpose = $2 AND expires_at > $3 AND used_at IS NULL FOR UPDATE").bind(&hash).bind(purpose.as_str()).bind(now).fetch_optional(connection(self.transaction)).await.map_err(db)?;
        let Some(row) = row else { return Ok(None) };
        let stored = TokenPurpose::from_str(&row.purpose).map_err(db)?;
        let value = SecureToken::from_storage(
            UserId::new(&row.user_id),
            row.token,
            stored,
            row.used_at,
            row.expires_at,
            row.created_at,
            row.updated_at,
        );
        if !value.verify(token) {
            return Ok(None);
        }
        sqlx::query("UPDATE secure_tokens SET used_at = $1, updated_at = $1 WHERE token = $2 AND purpose = $3").bind(now).bind(&hash).bind(purpose.as_str()).execute(connection(self.transaction)).await.map_err(db)?;
        let mut value = value;
        value.used_at = Some(now);
        value.updated_at = now;
        Ok(Some(value))
    }
    async fn check_token(&mut self, token: &str, purpose: TokenPurpose) -> Result<bool, Error> {
        let hash = torii_core::crypto::hash_token(token);
        let now = Utc::now();
        let row = sqlx::query_as::<_, crate::repositories::token::SecureTokenRow>("SELECT user_id, token, purpose, used_at, expires_at, created_at, updated_at FROM secure_tokens WHERE token = $1 AND purpose = $2 AND expires_at > $3 AND used_at IS NULL").bind(&hash).bind(purpose.as_str()).bind(now).fetch_optional(connection(self.transaction)).await.map_err(db)?;
        let Some(row) = row else { return Ok(false) };
        let stored = TokenPurpose::from_str(&row.purpose).map_err(db)?;
        Ok(SecureToken::from_storage(
            UserId::new(&row.user_id),
            row.token,
            stored,
            row.used_at,
            row.expires_at,
            row.created_at,
            row.updated_at,
        )
        .verify(token))
    }
}

#[async_trait]
impl TransactionOAuthRepository for PostgresTransactionOAuth<'_> {
    async fn create_account(
        &mut self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        let now = Utc::now();
        sqlx::query_as::<_, PostgresOAuthAccount>("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES ($1, $2, $3, $4, $5) RETURNING id, user_id, provider, subject, created_at, updated_at").bind(user_id.as_str()).bind(provider).bind(subject).bind(now).bind(now).fetch_one(connection(self.transaction)).await.map(Into::into).map_err(db)
    }
    async fn find_user_by_provider(
        &mut self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error> {
        sqlx::query_as::<_, PostgresUser>("SELECT u.id, u.email, u.name, u.email_verified_at, u.locked_at, u.created_at, u.updated_at FROM users u INNER JOIN oauth_accounts oa ON u.id = oa.user_id WHERE oa.provider = $1 AND oa.subject = $2").bind(provider).bind(subject).fetch_optional(connection(self.transaction)).await.map(|v| v.map(Into::into)).map_err(db)
    }
    async fn find_account_by_provider(
        &mut self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        sqlx::query_as::<_, PostgresOAuthAccount>("SELECT id, user_id, provider, subject, created_at, updated_at FROM oauth_accounts WHERE provider = $1 AND subject = $2").bind(provider).bind(subject).fetch_optional(connection(self.transaction)).await.map(|v| v.map(Into::into)).map_err(db)
    }
    async fn find_accounts_by_user_id(&mut self, id: &UserId) -> Result<Vec<OAuthAccount>, Error> {
        sqlx::query_as::<_, PostgresOAuthAccount>("SELECT id, user_id, provider, subject, created_at, updated_at FROM oauth_accounts WHERE user_id = $1 ORDER BY created_at DESC").bind(id.as_str()).fetch_all(connection(self.transaction)).await.map(|v| v.into_iter().map(Into::into).collect()).map_err(db)
    }
    async fn link_account(
        &mut self,
        id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        let now = Utc::now();
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (provider, subject) DO NOTHING").bind(id.as_str()).bind(provider).bind(subject).bind(now).bind(now).execute(connection(self.transaction)).await.map(|_| ()).map_err(db)
    }
    async fn unlink_account(&mut self, id: &UserId, provider: &str) -> Result<(), Error> {
        sqlx::query("DELETE FROM oauth_accounts WHERE user_id = $1 AND provider = $2")
            .bind(id.as_str())
            .bind(provider)
            .execute(connection(self.transaction))
            .await
            .map(|_| ())
            .map_err(db)
    }
    async fn store_pkce_verifier(
        &mut self,
        state: &str,
        verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        let now = Utc::now();
        sqlx::query("INSERT INTO oauth_state (csrf_state, pkce_verifier, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (csrf_state) DO UPDATE SET pkce_verifier = $2, expires_at = $3, updated_at = $5").bind(state).bind(verifier).bind(now + expires_in).bind(now).bind(now).execute(connection(self.transaction)).await.map(|_| ()).map_err(db)
    }
    async fn get_pkce_verifier(&mut self, state: &str) -> Result<Option<String>, Error> {
        sqlx::query_scalar(
            "SELECT pkce_verifier FROM oauth_state WHERE csrf_state = $1 AND expires_at > $2",
        )
        .bind(state)
        .bind(Utc::now())
        .fetch_optional(connection(self.transaction))
        .await
        .map_err(db)
    }
    async fn delete_pkce_verifier(&mut self, state: &str) -> Result<(), Error> {
        sqlx::query("DELETE FROM oauth_state WHERE csrf_state = $1")
            .bind(state)
            .execute(connection(self.transaction))
            .await
            .map(|_| ())
            .map_err(db)
    }
}

#[derive(sqlx::FromRow)]
struct PasskeyRow {
    credential_id: String,
    user_id: String,
    public_key: String,
    name: Option<String>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

fn passkey(row: PasskeyRow) -> Result<PasskeyCredential, Error> {
    Ok(PasskeyCredential {
        user_id: UserId::new(&row.user_id),
        credential_id: BASE64_STANDARD.decode(row.credential_id).map_err(db)?,
        public_key: BASE64_STANDARD.decode(row.public_key).map_err(db)?,
        name: row.name,
        created_at: row.created_at,
        last_used_at: row.last_used_at,
    })
}

#[async_trait]
impl TransactionPasskeyRepository for PostgresTransactionPasskeys<'_> {
    async fn add_credential(
        &mut self,
        id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        name: Option<String>,
    ) -> Result<PasskeyCredential, Error> {
        let now = Utc::now();
        sqlx::query("INSERT INTO passkeys (credential_id, user_id, public_key, name, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)").bind(BASE64_STANDARD.encode(&credential_id)).bind(id.as_str()).bind(BASE64_STANDARD.encode(&public_key)).bind(&name).bind(now).bind(now).execute(connection(self.transaction)).await.map_err(db)?;
        self.get_credential(&credential_id)
            .await?
            .ok_or_else(|| db("Passkey not found"))
    }
    async fn get_credentials_for_user(
        &mut self,
        id: &UserId,
    ) -> Result<Vec<PasskeyCredential>, Error> {
        sqlx::query_as::<_, PasskeyRow>("SELECT credential_id, user_id, public_key, name, last_used_at, created_at FROM passkeys WHERE user_id = $1").bind(id.as_str()).fetch_all(connection(self.transaction)).await.map_err(db)?.into_iter().map(passkey).collect()
    }
    async fn get_credential(&mut self, id: &[u8]) -> Result<Option<PasskeyCredential>, Error> {
        sqlx::query_as::<_, PasskeyRow>("SELECT credential_id, user_id, public_key, name, last_used_at, created_at FROM passkeys WHERE credential_id = $1").bind(BASE64_STANDARD.encode(id)).fetch_optional(connection(self.transaction)).await.map_err(db)?.map(passkey).transpose()
    }
    async fn update_last_used(&mut self, id: &[u8]) -> Result<(), Error> {
        sqlx::query(
            "UPDATE passkeys SET last_used_at = $1, updated_at = $1 WHERE credential_id = $2",
        )
        .bind(Utc::now())
        .bind(BASE64_STANDARD.encode(id))
        .execute(connection(self.transaction))
        .await
        .map(|_| ())
        .map_err(db)
    }
    async fn delete_credential(&mut self, id: &[u8]) -> Result<(), Error> {
        sqlx::query("DELETE FROM passkeys WHERE credential_id = $1")
            .bind(BASE64_STANDARD.encode(id))
            .execute(connection(self.transaction))
            .await
            .map(|_| ())
            .map_err(db)
    }
    async fn delete_all_for_user(&mut self, id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM passkeys WHERE user_id = $1")
            .bind(id.as_str())
            .execute(connection(self.transaction))
            .await
            .map(|_| ())
            .map_err(db)
    }
}

impl TransactionalRepositoryProvider for PostgresRepositoryProvider {
    type Transaction<'a> = PostgresTransactionView<'a>;
    fn transaction<'a>(
        &'a self,
        transaction: &'a mut dyn TransactionAdapter,
    ) -> Result<Self::Transaction<'a>, Error> {
        let adapter = transaction
            .as_any_mut()
            .downcast_mut::<PostgresTransactionAdapter>()
            .ok_or_else(mismatch)?;
        Ok(PostgresTransactionView {
            transaction: &mut adapter.transaction,
        })
    }
}
