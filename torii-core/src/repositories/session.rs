use crate::{Error, Session, UserId, session::SessionToken, transaction::TransactionAdapter};
use async_trait::async_trait;
use chrono::Duration;

/// Repository for session data access
#[async_trait]
pub trait SessionRepository: Send + Sync + 'static {
    /// Create a new session
    async fn create(
        &self,
        transaction: &mut dyn TransactionAdapter,
        session: Session,
    ) -> Result<Session, Error>;

    /// Find a session by token
    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error>;

    /// Find all sessions for a user
    async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<Session>, Error>;

    /// Delete a session by token
    async fn delete(
        &self,
        transaction: &mut dyn TransactionAdapter,
        token: &SessionToken,
    ) -> Result<(), Error>;

    /// Delete all sessions for a user
    async fn delete_by_user_id(
        &self,
        transaction: &mut dyn TransactionAdapter,
        user_id: &UserId,
    ) -> Result<(), Error>;

    /// Clean up expired sessions
    async fn cleanup_expired(&self) -> Result<(), Error>;

    /// Refresh a session by extending its expiration time
    ///
    /// Returns the updated session with the new expiration time
    async fn refresh(
        &self,
        transaction: &mut dyn TransactionAdapter,
        token: &SessionToken,
        duration: Duration,
    ) -> Result<Session, Error>;
}
