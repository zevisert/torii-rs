use chrono::{DateTime, Duration, Utc};
use sqlx::{Sqlite, Transaction};
use torii_core::{
    Error, FailedLoginAttempt, NewUser, OAuthAccount, Session, User, UserId,
    error::StorageError,
    repositories::{
        TransactionBruteForceRepository, TransactionOAuthRepository, TransactionPasskeyRepository,
        TransactionPasswordRepository, TransactionRepositoryView, TransactionSessionRepository,
        TransactionTokenRepository, TransactionUserRepository, TransactionalRepositoryProvider,
    },
    session::SessionToken,
    storage::{AttemptStats, SecureToken, TokenPurpose},
    transaction::TransactionAdapter,
};

use crate::{SqliteTransactionAdapter, SqliteUser, oauth::SqliteOAuthAccount};

fn mismatch() -> Error {
    Error::Storage(StorageError::Database(
        "SQLite transaction adapter required".into(),
    ))
}

pub struct SqliteTransactionView<'a> {
    pub(crate) transaction: &'a mut Transaction<'static, Sqlite>,
}

impl TransactionRepositoryView for SqliteTransactionView<'_> {
    type Users<'a>
        = SqliteTransactionUsers<'a>
    where
        Self: 'a;
    type Passwords<'a>
        = SqliteTransactionPasswords<'a>
    where
        Self: 'a;
    type BruteForce<'a>
        = SqliteTransactionBruteForce<'a>
    where
        Self: 'a;
    type Sessions<'a>
        = SqliteTransactionSessions<'a>
    where
        Self: 'a;
    type Tokens<'a>
        = SqliteTransactionTokens<'a>
    where
        Self: 'a;
    type OAuth<'a>
        = SqliteTransactionOAuth<'a>
    where
        Self: 'a;
    type Passkeys<'a>
        = SqliteTransactionPasskeys<'a>
    where
        Self: 'a;

    fn users(&mut self) -> Self::Users<'_> {
        SqliteTransactionUsers {
            transaction: &mut *self.transaction,
        }
    }
    fn passwords(&mut self) -> Self::Passwords<'_> {
        SqliteTransactionPasswords {
            transaction: &mut *self.transaction,
        }
    }
    fn brute_force(&mut self) -> Self::BruteForce<'_> {
        SqliteTransactionBruteForce {
            transaction: &mut *self.transaction,
        }
    }
    fn sessions(&mut self) -> Self::Sessions<'_> {
        SqliteTransactionSessions {
            transaction: &mut *self.transaction,
        }
    }
    fn tokens(&mut self) -> Self::Tokens<'_> {
        SqliteTransactionTokens {
            transaction: &mut *self.transaction,
        }
    }
    fn oauth(&mut self) -> Self::OAuth<'_> {
        SqliteTransactionOAuth {
            transaction: &mut *self.transaction,
        }
    }
    fn passkeys(&mut self) -> Self::Passkeys<'_> {
        SqliteTransactionPasskeys {
            transaction: &mut *self.transaction,
        }
    }
}

macro_rules! tx_family {
    ($name:ident) => {
        pub struct $name<'a> {
            #[allow(dead_code)]
            transaction: &'a mut Transaction<'static, Sqlite>,
        }
    };
}

tx_family!(SqliteTransactionUsers);
tx_family!(SqliteTransactionPasswords);
tx_family!(SqliteTransactionBruteForce);
tx_family!(SqliteTransactionSessions);
tx_family!(SqliteTransactionTokens);
tx_family!(SqliteTransactionOAuth);
tx_family!(SqliteTransactionPasskeys);

#[async_trait::async_trait]
impl TransactionUserRepository for SqliteTransactionUsers<'_> {
    async fn create(&mut self, user: NewUser) -> Result<User, Error> {
        let now = Utc::now().timestamp();
        let row = sqlx::query_as::<_, SqliteUser>("INSERT INTO users (id,email,name,email_verified_at,created_at,updated_at) VALUES (?,?,?,?,?,?) RETURNING *")
            .bind(user.id.as_str()).bind(user.email).bind(user.name)
            .bind(user.email_verified_at.map(|v| v.timestamp())).bind(now).bind(now)
            .fetch_one(&mut **self.transaction).await.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(row.into())
    }
    async fn find_by_id(&mut self, id: &UserId) -> Result<Option<User>, Error> {
        let row = sqlx::query_as::<_, SqliteUser>("SELECT * FROM users WHERE id = ?")
            .bind(id.as_str())
            .fetch_optional(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(row.map(Into::into))
    }
    async fn find_by_email(&mut self, email: &str) -> Result<Option<User>, Error> {
        let row = sqlx::query_as::<_, SqliteUser>("SELECT * FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(row.map(Into::into))
    }
    async fn delete(&mut self, id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.as_str())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl TransactionPasswordRepository for SqliteTransactionPasswords<'_> {
    async fn set_password_hash(&mut self, id: &UserId, hash: &str) -> Result<(), Error> {
        sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(hash)
            .bind(Utc::now().timestamp())
            .bind(id.as_str())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
    async fn get_password_hash(&mut self, id: &UserId) -> Result<Option<String>, Error> {
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
            .bind(id.as_str())
            .fetch_optional(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))
    }
}

#[derive(sqlx::FromRow)]
struct AttemptRow {
    count: i32,
    latest_at: Option<i64>,
}

#[async_trait::async_trait]
impl TransactionBruteForceRepository for SqliteTransactionBruteForce<'_> {
    async fn record_failed_attempt(
        &mut self,
        email: &str,
        ip: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: i64,
            email: String,
            ip_address: Option<String>,
            attempted_at: i64,
        }
        let row = sqlx::query_as::<_, Row>("INSERT INTO failed_login_attempts (email,ip_address,attempted_at) VALUES (?,?,?) RETURNING id,email,ip_address,attempted_at")
            .bind(email).bind(ip).bind(Utc::now().timestamp()).fetch_one(&mut **self.transaction).await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(FailedLoginAttempt {
            id: row.id,
            email: row.email,
            ip_address: row.ip_address,
            attempted_at: DateTime::from_timestamp(row.attempted_at, 0).expect("invalid timestamp"),
        })
    }
    async fn get_attempt_stats(
        &mut self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error> {
        let row = sqlx::query_as::<_, AttemptRow>("SELECT COUNT(*) as count, MAX(attempted_at) as latest_at FROM failed_login_attempts WHERE email = ? AND attempted_at >= ?")
            .bind(email).bind(since.timestamp()).fetch_one(&mut **self.transaction).await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(AttemptStats {
            count: row.count as u32,
            latest_at: row.latest_at.and_then(|v| DateTime::from_timestamp(v, 0)),
        })
    }
    async fn clear_attempts(&mut self, email: &str) -> Result<u64, Error> {
        Ok(
            sqlx::query("DELETE FROM failed_login_attempts WHERE email = ?")
                .bind(email)
                .execute(&mut **self.transaction)
                .await
                .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?
                .rows_affected(),
        )
    }
    async fn set_locked_at(
        &mut self,
        email: &str,
        locked_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        sqlx::query("UPDATE users SET locked_at = ? WHERE email = ?")
            .bind(locked_at.map(|v| v.timestamp()))
            .bind(email)
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
    async fn get_locked_at(&mut self, email: &str) -> Result<Option<DateTime<Utc>>, Error> {
        let row: Option<(Option<i64>,)> =
            sqlx::query_as("SELECT locked_at FROM users WHERE email = ?")
                .bind(email)
                .fetch_optional(&mut **self.transaction)
                .await
                .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(row
            .and_then(|v| v.0)
            .and_then(|v| DateTime::from_timestamp(v, 0)))
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    token: String,
    user_id: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
}
fn session(row: SessionRow, token: &SessionToken) -> Option<Session> {
    if !token.verify_hash(&row.token) {
        return None;
    }
    Some(Session {
        token: Some(token.clone()),
        token_hash: row.token,
        user_id: UserId::new(&row.user_id),
        user_agent: row.user_agent,
        ip_address: row.ip_address,
        created_at: DateTime::from_timestamp(row.created_at, 0)?,
        updated_at: DateTime::from_timestamp(row.updated_at, 0)?,
        expires_at: DateTime::from_timestamp(row.expires_at, 0)?,
    })
}

#[async_trait::async_trait]
impl TransactionSessionRepository for SqliteTransactionSessions<'_> {
    async fn create(&mut self, session: Session) -> Result<Session, Error> {
        sqlx::query("INSERT INTO sessions (token,user_id,user_agent,ip_address,created_at,updated_at,expires_at) VALUES (?,?,?,?,?,?,?)")
            .bind(&session.token_hash).bind(session.user_id.as_str()).bind(&session.user_agent).bind(&session.ip_address).bind(session.created_at.timestamp()).bind(session.updated_at.timestamp()).bind(session.expires_at.timestamp()).execute(&mut **self.transaction).await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(session)
    }
    async fn find_by_token(&mut self, token: &SessionToken) -> Result<Option<Session>, Error> {
        let row = sqlx::query_as::<_, SessionRow>("SELECT token,user_id,user_agent,ip_address,created_at,updated_at,expires_at FROM sessions WHERE token = ?").bind(token.token_hash()).fetch_optional(&mut **self.transaction).await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(row.and_then(|v| session(v, token)))
    }
    async fn find_by_user_id(&mut self, id: &UserId) -> Result<Vec<Session>, Error> {
        let rows = sqlx::query_as::<_, SessionRow>("SELECT token,user_id,user_agent,ip_address,created_at,updated_at,expires_at FROM sessions WHERE user_id = ?").bind(id.as_str()).fetch_all(&mut **self.transaction).await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                Some(Session {
                    token: None,
                    token_hash: row.token,
                    user_id: UserId::new(&row.user_id),
                    user_agent: row.user_agent,
                    ip_address: row.ip_address,
                    created_at: DateTime::from_timestamp(row.created_at, 0)?,
                    updated_at: DateTime::from_timestamp(row.updated_at, 0)?,
                    expires_at: DateTime::from_timestamp(row.expires_at, 0)?,
                })
            })
            .collect())
    }
    async fn delete(&mut self, token: &SessionToken) -> Result<(), Error> {
        sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(token.token_hash())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
    async fn delete_by_user_id(&mut self, id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(id.as_str())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
    async fn refresh(
        &mut self,
        token: &SessionToken,
        duration: Duration,
    ) -> Result<Session, Error> {
        let expires = (Utc::now() + duration).timestamp();
        sqlx::query("UPDATE sessions SET expires_at = ?, updated_at = ? WHERE token = ?")
            .bind(expires)
            .bind(Utc::now().timestamp())
            .bind(token.token_hash())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        self.find_by_token(token)
            .await?
            .ok_or_else(|| Error::Storage(StorageError::Database("Session not found".into())))
    }
}

#[async_trait::async_trait]
impl TransactionOAuthRepository for SqliteTransactionOAuth<'_> {
    async fn create_account(
        &mut self,
        provider: &str,
        subject: &str,
        id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        self.link_account(id, provider, subject).await?;
        self.find_account_by_provider(provider, subject)
            .await?
            .ok_or_else(|| Error::Storage(StorageError::Database("OAuth account not found".into())))
    }
    async fn find_user_by_provider(
        &mut self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error> {
        let row = sqlx::query_as::<_, SqliteUser>("SELECT u.* FROM users u JOIN oauth_accounts a ON a.user_id=u.id WHERE a.provider=? AND a.subject=?").bind(provider).bind(subject).fetch_optional(&mut **self.transaction).await.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(row.map(Into::into))
    }
    async fn find_account_by_provider(
        &mut self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        let row = sqlx::query_as::<_, SqliteOAuthAccount>("SELECT id,user_id,provider,subject,created_at,updated_at FROM oauth_accounts WHERE provider=? AND subject=?").bind(provider).bind(subject).fetch_optional(&mut **self.transaction).await.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(row.map(Into::into))
    }
    async fn find_accounts_by_user_id(&mut self, id: &UserId) -> Result<Vec<OAuthAccount>, Error> {
        let rows = sqlx::query_as::<_, SqliteOAuthAccount>("SELECT id,user_id,provider,subject,created_at,updated_at FROM oauth_accounts WHERE user_id=?").bind(id.as_str()).fetch_all(&mut **self.transaction).await.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
    async fn link_account(
        &mut self,
        id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        sqlx::query("INSERT INTO oauth_accounts (user_id,provider,subject,created_at,updated_at) VALUES (?,?,?,?,?)").bind(id.as_str()).bind(provider).bind(subject).bind(Utc::now().timestamp()).bind(Utc::now().timestamp()).execute(&mut **self.transaction).await.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
    async fn unlink_account(&mut self, id: &UserId, provider: &str) -> Result<(), Error> {
        sqlx::query("DELETE FROM oauth_accounts WHERE user_id=? AND provider=?")
            .bind(id.as_str())
            .bind(provider)
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
    async fn store_pkce_verifier(
        &mut self,
        state: &str,
        verifier: &str,
        expires: Duration,
    ) -> Result<(), Error> {
        sqlx::query("INSERT INTO oauth_state (csrf_state,pkce_verifier,expires_at) VALUES (?,?,?)")
            .bind(state)
            .bind(verifier)
            .bind((Utc::now() + expires).timestamp())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
    async fn get_pkce_verifier(&mut self, state: &str) -> Result<Option<String>, Error> {
        sqlx::query_scalar(
            "SELECT pkce_verifier FROM oauth_state WHERE csrf_state=? AND expires_at > ?",
        )
        .bind(state)
        .bind(Utc::now().timestamp())
        .fetch_optional(&mut **self.transaction)
        .await
        .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))
    }
    async fn delete_pkce_verifier(&mut self, state: &str) -> Result<(), Error> {
        sqlx::query("DELETE FROM oauth_state WHERE csrf_state=?")
            .bind(state)
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct PasskeyRow {
    user_id: String,
    credential_id: String,
    public_key: String,
    created_at: i64,
    updated_at: i64,
}
fn passkey(row: PasskeyRow) -> Option<torii_core::repositories::PasskeyCredential> {
    Some(torii_core::repositories::PasskeyCredential {
        user_id: UserId::new(&row.user_id),
        credential_id: row.credential_id.into_bytes(),
        public_key: row.public_key.into_bytes(),
        name: None,
        created_at: DateTime::from_timestamp(row.created_at, 0)?,
        last_used_at: DateTime::from_timestamp(row.updated_at, 0),
    })
}

#[async_trait::async_trait]
impl TransactionPasskeyRepository for SqliteTransactionPasskeys<'_> {
    async fn add_credential(
        &mut self,
        id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        _name: Option<String>,
    ) -> Result<torii_core::repositories::PasskeyCredential, Error> {
        sqlx::query("INSERT INTO passkeys (credential_id,user_id,public_key) VALUES (?,?,?)")
            .bind(String::from_utf8_lossy(&credential_id).to_string())
            .bind(id.as_str())
            .bind(String::from_utf8_lossy(&public_key).to_string())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        self.get_credential(&credential_id)
            .await?
            .ok_or_else(|| Error::Storage(StorageError::Database("Passkey not found".into())))
    }
    async fn get_credentials_for_user(
        &mut self,
        id: &UserId,
    ) -> Result<Vec<torii_core::repositories::PasskeyCredential>, Error> {
        let rows = sqlx::query_as::<_, PasskeyRow>("SELECT user_id,credential_id,public_key,created_at,updated_at FROM passkeys WHERE user_id=?").bind(id.as_str()).fetch_all(&mut **self.transaction).await.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(rows.into_iter().filter_map(passkey).collect())
    }
    async fn get_credential(
        &mut self,
        id: &[u8],
    ) -> Result<Option<torii_core::repositories::PasskeyCredential>, Error> {
        let row = sqlx::query_as::<_, PasskeyRow>("SELECT user_id,credential_id,public_key,created_at,updated_at FROM passkeys WHERE credential_id=?").bind(String::from_utf8_lossy(id).to_string()).fetch_optional(&mut **self.transaction).await.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(row.and_then(passkey))
    }
    async fn update_last_used(&mut self, id: &[u8]) -> Result<(), Error> {
        sqlx::query("UPDATE passkeys SET updated_at=? WHERE credential_id=?")
            .bind(Utc::now().timestamp())
            .bind(String::from_utf8_lossy(id).to_string())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
    async fn delete_credential(&mut self, id: &[u8]) -> Result<(), Error> {
        sqlx::query("DELETE FROM passkeys WHERE credential_id=?")
            .bind(String::from_utf8_lossy(id).to_string())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
    async fn delete_all_for_user(&mut self, id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM passkeys WHERE user_id=?")
            .bind(id.as_str())
            .execute(&mut **self.transaction)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl TransactionTokenRepository for SqliteTransactionTokens<'_> {
    async fn create_token(
        &mut self,
        _id: &UserId,
        _purpose: TokenPurpose,
        _expires: Duration,
    ) -> Result<SecureToken, Error> {
        Err(Error::Storage(StorageError::Database(
            "SQLite token repository not yet implemented".into(),
        )))
    }
    async fn verify_token(
        &mut self,
        _token: &str,
        _purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        Err(Error::Storage(StorageError::Database(
            "SQLite token repository not yet implemented".into(),
        )))
    }
    async fn check_token(&mut self, _token: &str, _purpose: TokenPurpose) -> Result<bool, Error> {
        Err(Error::Storage(StorageError::Database(
            "SQLite token repository not yet implemented".into(),
        )))
    }
}

impl TransactionalRepositoryProvider for crate::SqliteRepositoryProvider {
    type Transaction<'a> = SqliteTransactionView<'a>;
    fn transaction<'a>(
        &'a self,
        transaction: &'a mut dyn TransactionAdapter,
    ) -> Result<Self::Transaction<'a>, Error> {
        let adapter = transaction
            .as_any_mut()
            .downcast_mut::<SqliteTransactionAdapter>()
            .ok_or_else(mismatch)?;
        Ok(SqliteTransactionView {
            transaction: &mut adapter.transaction,
        })
    }
}
