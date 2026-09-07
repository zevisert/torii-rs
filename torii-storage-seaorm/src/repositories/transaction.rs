use async_trait::async_trait;
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Duration, Utc};
use rand::{TryRngCore, rngs::OsRng};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect,
};
use std::str::FromStr;
use torii_core::{
    Error, FailedLoginAttempt, NewUser, OAuthAccount, Session, User, UserId,
    repositories::{
        PasskeyCredential, TransactionBruteForceRepository, TransactionOAuthRepository,
        TransactionPasskeyRepository, TransactionPasswordRepository, TransactionRepositoryView,
        TransactionSessionRepository, TransactionTokenRepository, TransactionUserRepository,
    },
    session::SessionToken,
    storage::{AttemptStats, SecureToken, TokenPurpose},
};

use crate::{
    SeaORMTransactionAdapter,
    entities::{failed_login_attempt, oauth, passkey, pkce_verifier, secure_token, session, user},
};

fn db_error(error: impl ToString) -> Error {
    Error::Storage(torii_core::error::StorageError::Database(error.to_string()))
}

fn passkey_from_model(model: passkey::Model) -> Result<PasskeyCredential, Error> {
    let json: serde_json::Value = serde_json::from_str(&model.data_json).map_err(db_error)?;
    Ok(PasskeyCredential {
        user_id: UserId::new(&model.user_id),
        credential_id: BASE64_STANDARD
            .decode(json["credential_id"].as_str().unwrap_or(""))
            .map_err(db_error)?,
        public_key: BASE64_STANDARD
            .decode(json["public_key"].as_str().unwrap_or(""))
            .map_err(db_error)?,
        name: json["name"].as_str().map(str::to_owned),
        created_at: serde_json::from_value(json["created_at"].clone())
            .unwrap_or_else(|_| Utc::now()),
        last_used_at: serde_json::from_value(json["last_used_at"].clone()).unwrap_or(None),
    })
}

pub struct SeaORMTransaction<'a> {
    db: &'a DatabaseTransaction,
}

impl<'a> SeaORMTransaction<'a> {
    pub fn new(transaction: &'a mut dyn torii_core::TransactionAdapter) -> Result<Self, Error> {
        let adapter = transaction
            .as_any_mut()
            .downcast_mut::<SeaORMTransactionAdapter>()
            .ok_or_else(|| db_error("SeaORM transaction adapter required"))?;
        Ok(Self {
            db: adapter.transaction(),
        })
    }
}

pub struct SeaORMUsers<'a> {
    db: &'a DatabaseTransaction,
}
pub struct SeaORMPasswords<'a> {
    db: &'a DatabaseTransaction,
}
pub struct SeaORMBruteForce<'a> {
    db: &'a DatabaseTransaction,
}
pub struct SeaORMSessions<'a> {
    db: &'a DatabaseTransaction,
}
pub struct SeaORMTokens<'a> {
    db: &'a DatabaseTransaction,
}
pub struct SeaORMOAuth<'a> {
    db: &'a DatabaseTransaction,
}
pub struct SeaORMPasskeys<'a> {
    db: &'a DatabaseTransaction,
}

impl<'a> TransactionRepositoryView for SeaORMTransaction<'a> {
    type Users<'b>
        = SeaORMUsers<'b>
    where
        Self: 'b;
    type Passwords<'b>
        = SeaORMPasswords<'b>
    where
        Self: 'b;
    type BruteForce<'b>
        = SeaORMBruteForce<'b>
    where
        Self: 'b;
    type Sessions<'b>
        = SeaORMSessions<'b>
    where
        Self: 'b;
    type Tokens<'b>
        = SeaORMTokens<'b>
    where
        Self: 'b;
    type OAuth<'b>
        = SeaORMOAuth<'b>
    where
        Self: 'b;
    type Passkeys<'b>
        = SeaORMPasskeys<'b>
    where
        Self: 'b;
    fn users(&mut self) -> Self::Users<'_> {
        SeaORMUsers { db: self.db }
    }
    fn passwords(&mut self) -> Self::Passwords<'_> {
        SeaORMPasswords { db: self.db }
    }
    fn brute_force(&mut self) -> Self::BruteForce<'_> {
        SeaORMBruteForce { db: self.db }
    }
    fn sessions(&mut self) -> Self::Sessions<'_> {
        SeaORMSessions { db: self.db }
    }
    fn tokens(&mut self) -> Self::Tokens<'_> {
        SeaORMTokens { db: self.db }
    }
    fn oauth(&mut self) -> Self::OAuth<'_> {
        SeaORMOAuth { db: self.db }
    }
    fn passkeys(&mut self) -> Self::Passkeys<'_> {
        SeaORMPasskeys { db: self.db }
    }
}

#[async_trait]
impl TransactionUserRepository for SeaORMUsers<'_> {
    async fn create(&mut self, value: NewUser) -> Result<User, Error> {
        user::ActiveModel {
            id: Set(value.id.to_string()),
            email: Set(value.email),
            name: Set(value.name),
            email_verified_at: Set(value.email_verified_at),
            ..Default::default()
        }
        .insert(self.db)
        .await
        .map(Into::into)
        .map_err(db_error)
    }
    async fn find_by_id(&mut self, id: &UserId) -> Result<Option<User>, Error> {
        Ok(user::Entity::find_by_id(id.as_str())
            .one(self.db)
            .await
            .map_err(db_error)?
            .map(Into::into))
    }
    async fn find_by_email(&mut self, email: &str) -> Result<Option<User>, Error> {
        Ok(user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(self.db)
            .await
            .map_err(db_error)?
            .map(Into::into))
    }
    async fn delete(&mut self, id: &UserId) -> Result<(), Error> {
        user::Entity::delete_by_id(id.as_str())
            .exec(self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

#[async_trait]
impl TransactionPasswordRepository for SeaORMPasswords<'_> {
    async fn set_password_hash(&mut self, id: &UserId, hash: &str) -> Result<(), Error> {
        let mut model: user::ActiveModel = user::Entity::find_by_id(id.as_str())
            .one(self.db)
            .await
            .map_err(db_error)?
            .ok_or_else(|| db_error("User not found"))?
            .into();
        model.password_hash = Set(Some(hash.to_owned()));
        model.update(self.db).await.map_err(db_error)?;
        Ok(())
    }
    async fn get_password_hash(&mut self, id: &UserId) -> Result<Option<String>, Error> {
        Ok(user::Entity::find_by_id(id.as_str())
            .one(self.db)
            .await
            .map_err(db_error)?
            .and_then(|u| u.password_hash))
    }
}

#[async_trait]
impl TransactionBruteForceRepository for SeaORMBruteForce<'_> {
    async fn record_failed_attempt(
        &mut self,
        email: &str,
        ip: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error> {
        let model = failed_login_attempt::ActiveModel {
            email: Set(email.to_owned()),
            ip_address: Set(ip.map(str::to_owned)),
            attempted_at: Set(Utc::now()),
            ..Default::default()
        }
        .insert(self.db)
        .await
        .map_err(db_error)?;
        Ok(FailedLoginAttempt {
            id: model.id,
            email: model.email,
            ip_address: model.ip_address,
            attempted_at: model.attempted_at,
        })
    }
    async fn get_attempt_stats(
        &mut self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error> {
        use sea_orm::sea_query::Expr;
        Ok(failed_login_attempt::Entity::find()
            .filter(failed_login_attempt::Column::Email.eq(email))
            .filter(failed_login_attempt::Column::AttemptedAt.gte(since))
            .select_only()
            .column_as(Expr::col(failed_login_attempt::Column::Id).count(), "count")
            .column_as(
                Expr::col(failed_login_attempt::Column::AttemptedAt).max(),
                "latest_at",
            )
            .into_tuple::<(i64, Option<DateTime<Utc>>)>()
            .one(self.db)
            .await
            .map_err(db_error)?
            .map(|(count, latest_at)| AttemptStats {
                count: count as u32,
                latest_at,
            })
            .unwrap_or_default())
    }
    async fn clear_attempts(&mut self, email: &str) -> Result<u64, Error> {
        Ok(failed_login_attempt::Entity::delete_many()
            .filter(failed_login_attempt::Column::Email.eq(email))
            .exec(self.db)
            .await
            .map_err(db_error)?
            .rows_affected)
    }
    async fn set_locked_at(
        &mut self,
        email: &str,
        locked_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        if let Some(model) = user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(self.db)
            .await
            .map_err(db_error)?
        {
            let mut active: user::ActiveModel = model.into();
            active.locked_at = Set(locked_at);
            active.updated_at = Set(Utc::now());
            active.update(self.db).await.map_err(db_error)?;
        }
        Ok(())
    }
    async fn get_locked_at(&mut self, email: &str) -> Result<Option<DateTime<Utc>>, Error> {
        Ok(user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(self.db)
            .await
            .map_err(db_error)?
            .and_then(|u| u.locked_at))
    }
}

fn session_from_model(model: session::Model, token: Option<SessionToken>) -> Session {
    Session {
        token,
        token_hash: model.token,
        user_id: UserId::new(&model.user_id),
        user_agent: model.user_agent,
        ip_address: model.ip_address,
        created_at: model.created_at,
        updated_at: model.updated_at,
        expires_at: model.expires_at,
    }
}

#[async_trait]
impl TransactionSessionRepository for SeaORMSessions<'_> {
    async fn create(&mut self, value: Session) -> Result<Session, Error> {
        let model = session::ActiveModel {
            user_id: Set(value.user_id.to_string()),
            token: Set(value.token_hash.clone()),
            ip_address: Set(value.ip_address.clone()),
            user_agent: Set(value.user_agent.clone()),
            expires_at: Set(value.expires_at),
            ..Default::default()
        }
        .insert(self.db)
        .await
        .map_err(db_error)?;
        Ok(session_from_model(model, value.token))
    }
    async fn find_by_token(&mut self, token: &SessionToken) -> Result<Option<Session>, Error> {
        let hash = token.token_hash();
        Ok(session::Entity::find()
            .filter(session::Column::Token.eq(hash))
            .one(self.db)
            .await
            .map_err(db_error)?
            .filter(|m| token.verify_hash(&m.token))
            .map(|m| session_from_model(m, Some(token.clone()))))
    }
    async fn find_by_user_id(&mut self, id: &UserId) -> Result<Vec<Session>, Error> {
        Ok(session::Entity::find()
            .filter(session::Column::UserId.eq(id.as_str()))
            .order_by_desc(session::Column::CreatedAt)
            .all(self.db)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(|m| session_from_model(m, None))
            .collect())
    }
    async fn delete(&mut self, token: &SessionToken) -> Result<(), Error> {
        session::Entity::delete_many()
            .filter(session::Column::Token.eq(token.token_hash()))
            .exec(self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
    async fn delete_by_user_id(&mut self, id: &UserId) -> Result<(), Error> {
        session::Entity::delete_many()
            .filter(session::Column::UserId.eq(id.as_str()))
            .exec(self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
    async fn refresh(
        &mut self,
        token: &SessionToken,
        duration: Duration,
    ) -> Result<Session, Error> {
        let model = session::Entity::find()
            .filter(session::Column::Token.eq(token.token_hash()))
            .one(self.db)
            .await
            .map_err(db_error)?
            .ok_or_else(|| db_error("Session not found"))?;
        let mut active: session::ActiveModel = model.into();
        active.expires_at = Set(Utc::now() + duration);
        active.updated_at = Set(Utc::now());
        Ok(session_from_model(
            active.update(self.db).await.map_err(db_error)?,
            Some(token.clone()),
        ))
    }
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("system RNG unavailable");
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

#[async_trait]
impl TransactionTokenRepository for SeaORMTokens<'_> {
    async fn create_token(
        &mut self,
        id: &UserId,
        purpose: TokenPurpose,
        expires_in: Duration,
    ) -> Result<SecureToken, Error> {
        let token = generate_token();
        let hash = torii_core::crypto::hash_token(&token);
        let now = Utc::now();
        let model = secure_token::ActiveModel {
            user_id: Set(id.to_string()),
            token: Set(hash.clone()),
            purpose: Set(purpose.as_str().to_owned()),
            used_at: Set(None),
            expires_at: Set(now + expires_in),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(self.db)
        .await
        .map_err(db_error)?;
        Ok(SecureToken::new(
            id.clone(),
            token,
            hash,
            purpose,
            None,
            model.expires_at,
            model.created_at,
            model.updated_at,
        ))
    }
    async fn verify_token(
        &mut self,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        let now = Utc::now();
        let hash = torii_core::crypto::hash_token(token);
        let row = secure_token::Entity::find()
            .filter(secure_token::Column::Token.eq(hash))
            .filter(secure_token::Column::Purpose.eq(purpose.as_str()))
            .filter(secure_token::Column::ExpiresAt.gt(now))
            .filter(secure_token::Column::UsedAt.is_null())
            .one(self.db)
            .await
            .map_err(db_error)?;
        let Some(row) = row else { return Ok(None) };
        let stored = TokenPurpose::from_str(&row.purpose).map_err(db_error)?;
        let result = SecureToken::from_storage(
            UserId::new(&row.user_id),
            row.token.clone(),
            stored,
            row.used_at,
            row.expires_at,
            row.created_at,
            row.updated_at,
        );
        if !result.verify(token) {
            return Ok(None);
        }
        let mut active: secure_token::ActiveModel = row.into();
        active.used_at = Set(Some(now));
        active.updated_at = Set(now);
        active.update(self.db).await.map_err(db_error)?;
        let mut result = result;
        result.used_at = Some(now);
        result.updated_at = now;
        Ok(Some(result))
    }
    async fn check_token(&mut self, token: &str, purpose: TokenPurpose) -> Result<bool, Error> {
        let hash = torii_core::crypto::hash_token(token);
        let now = Utc::now();
        let row = secure_token::Entity::find()
            .filter(secure_token::Column::Token.eq(hash))
            .filter(secure_token::Column::Purpose.eq(purpose.as_str()))
            .filter(secure_token::Column::ExpiresAt.gt(now))
            .filter(secure_token::Column::UsedAt.is_null())
            .one(self.db)
            .await
            .map_err(db_error)?;
        let Some(row) = row else { return Ok(false) };
        let stored = TokenPurpose::from_str(&row.purpose).map_err(db_error)?;
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

fn account(model: oauth::Model) -> Result<OAuthAccount, Error> {
    OAuthAccount::builder()
        .user_id(UserId::new(&model.user_id))
        .provider(model.provider)
        .subject(model.subject)
        .created_at(model.created_at)
        .updated_at(model.updated_at)
        .build()
        .map_err(db_error)
}

#[async_trait]
impl TransactionOAuthRepository for SeaORMOAuth<'_> {
    async fn create_account(
        &mut self,
        provider: &str,
        subject: &str,
        id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        let user = user::Entity::find_by_id(id.as_str())
            .one(self.db)
            .await
            .map_err(db_error)?
            .ok_or_else(|| db_error("User not found"))?;
        account(
            oauth::ActiveModel {
                user_id: Set(user.id),
                provider: Set(provider.to_owned()),
                subject: Set(subject.to_owned()),
                ..Default::default()
            }
            .insert(self.db)
            .await
            .map_err(db_error)?,
        )
    }
    async fn find_user_by_provider(
        &mut self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error> {
        let Some(account) = oauth::Entity::find()
            .filter(oauth::Column::Provider.eq(provider))
            .filter(oauth::Column::Subject.eq(subject))
            .one(self.db)
            .await
            .map_err(db_error)?
        else {
            return Ok(None);
        };
        Ok(user::Entity::find_by_id(account.user_id)
            .one(self.db)
            .await
            .map_err(db_error)?
            .map(Into::into))
    }
    async fn find_account_by_provider(
        &mut self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        Ok(oauth::Entity::find()
            .filter(oauth::Column::Provider.eq(provider))
            .filter(oauth::Column::Subject.eq(subject))
            .one(self.db)
            .await
            .map_err(db_error)?
            .map(account)
            .transpose()?)
    }
    async fn find_accounts_by_user_id(&mut self, id: &UserId) -> Result<Vec<OAuthAccount>, Error> {
        oauth::Entity::find()
            .filter(oauth::Column::UserId.eq(id.as_str()))
            .order_by_desc(oauth::Column::CreatedAt)
            .all(self.db)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(account)
            .collect()
    }
    async fn link_account(
        &mut self,
        id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        self.create_account(provider, subject, id).await.map(|_| ())
    }
    async fn unlink_account(&mut self, id: &UserId, provider: &str) -> Result<(), Error> {
        oauth::Entity::delete_many()
            .filter(oauth::Column::UserId.eq(id.as_str()))
            .filter(oauth::Column::Provider.eq(provider))
            .exec(self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
    async fn store_pkce_verifier(
        &mut self,
        state: &str,
        verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        pkce_verifier::ActiveModel {
            csrf_state: Set(state.to_owned()),
            verifier: Set(verifier.to_owned()),
            expires_at: Set(Utc::now() + expires_in),
            ..Default::default()
        }
        .insert(self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }
    async fn get_pkce_verifier(&mut self, state: &str) -> Result<Option<String>, Error> {
        Ok(pkce_verifier::Entity::find()
            .filter(pkce_verifier::Column::CsrfState.eq(state))
            .filter(pkce_verifier::Column::ExpiresAt.gt(Utc::now()))
            .one(self.db)
            .await
            .map_err(db_error)?
            .map(|m| m.verifier))
    }
    async fn delete_pkce_verifier(&mut self, state: &str) -> Result<(), Error> {
        pkce_verifier::Entity::delete_many()
            .filter(pkce_verifier::Column::CsrfState.eq(state))
            .exec(self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

#[async_trait]
impl TransactionPasskeyRepository for SeaORMPasskeys<'_> {
    async fn add_credential(
        &mut self,
        id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        name: Option<String>,
    ) -> Result<PasskeyCredential, Error> {
        let credential_id_b64 = BASE64_STANDARD.encode(&credential_id);
        let json = serde_json::json!({"credential_id": credential_id_b64, "public_key": BASE64_STANDARD.encode(&public_key), "name": name, "created_at": Utc::now(), "last_used_at": Option::<DateTime<Utc>>::None});
        passkey::ActiveModel {
            user_id: Set(id.to_string()),
            credential_id: Set(credential_id_b64),
            data_json: Set(json.to_string()),
            ..Default::default()
        }
        .insert(self.db)
        .await
        .map_err(db_error)?;
        Ok(PasskeyCredential {
            user_id: id.clone(),
            credential_id,
            public_key,
            name,
            created_at: Utc::now(),
            last_used_at: None,
        })
    }
    async fn get_credentials_for_user(
        &mut self,
        id: &UserId,
    ) -> Result<Vec<PasskeyCredential>, Error> {
        passkey::Entity::find()
            .filter(passkey::Column::UserId.eq(id.as_str()))
            .all(self.db)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(passkey_from_model)
            .collect()
    }
    async fn get_credential(
        &mut self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, Error> {
        Ok(passkey::Entity::find()
            .filter(passkey::Column::CredentialId.eq(BASE64_STANDARD.encode(credential_id)))
            .one(self.db)
            .await
            .map_err(db_error)?
            .map(passkey_from_model)
            .transpose()?)
    }
    async fn update_last_used(&mut self, credential_id: &[u8]) -> Result<(), Error> {
        if let Some(model) = passkey::Entity::find()
            .filter(passkey::Column::CredentialId.eq(BASE64_STANDARD.encode(credential_id)))
            .one(self.db)
            .await
            .map_err(db_error)?
        {
            let mut json: serde_json::Value =
                serde_json::from_str(&model.data_json).map_err(db_error)?;
            json["last_used_at"] = serde_json::json!(Utc::now());
            let mut active: passkey::ActiveModel = model.into();
            active.data_json = Set(json.to_string());
            active.update(self.db).await.map_err(db_error)?;
        }
        Ok(())
    }
    async fn delete_credential(&mut self, credential_id: &[u8]) -> Result<(), Error> {
        passkey::Entity::delete_many()
            .filter(passkey::Column::CredentialId.eq(BASE64_STANDARD.encode(credential_id)))
            .exec(self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
    async fn delete_all_for_user(&mut self, id: &UserId) -> Result<(), Error> {
        passkey::Entity::delete_many()
            .filter(passkey::Column::UserId.eq(id.as_str()))
            .exec(self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}
