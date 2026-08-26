use std::sync::Arc;
use torii_core::{
    Error, User, UserId, repositories::UserRepository, storage::NewUser, validation::validate_email,
};

/// Service for user management operations
pub struct UserService<R: UserRepository> {
    repository: Arc<R>,
}

impl<R: UserRepository> UserService<R> {
    /// Create a new UserService with the given repository
    pub fn new(repository: Arc<R>) -> Self {
        Self { repository }
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        transaction: &mut dyn torii_core::TransactionAdapter,
        email: &str,
        name: Option<String>,
    ) -> Result<User, Error> {
        // Validate email format
        validate_email(email)?;

        let mut builder = NewUser::builder()
            .id(UserId::new_random())
            .email(email.to_string());

        if let Some(name) = name {
            builder = builder.name(name);
        }

        let new_user = builder.build()?;

        let user = self.repository.create(transaction, new_user).await?;
        Ok(user)
    }

    /// Get a user by ID
    pub async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, Error> {
        self.repository.find_by_id(user_id).await
    }

    /// Get a user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        self.repository.find_by_email(email).await
    }

    /// Get or create a user by email
    pub async fn get_or_create_user(
        &self,
        transaction: &mut dyn torii_core::TransactionAdapter,
        email: &str,
    ) -> Result<User, Error> {
        // Validate email format
        validate_email(email)?;

        if let Some(user) = self.repository.find_by_email(email).await? {
            return Ok(user);
        }

        self.create_user(transaction, email, None).await
    }

    /// Update a user
    pub async fn update_user(
        &self,
        transaction: &mut dyn torii_core::TransactionAdapter,
        user: &User,
    ) -> Result<User, Error> {
        let user = self.repository.update(transaction, user).await?;
        Ok(user)
    }

    /// Delete a user
    pub async fn delete_user(
        &self,
        transaction: &mut dyn torii_core::TransactionAdapter,
        user_id: &UserId,
    ) -> Result<(), Error> {
        self.repository.delete(transaction, user_id).await?;
        Ok(())
    }

    /// Mark a user's email as verified
    pub async fn verify_email(
        &self,
        transaction: &mut dyn torii_core::TransactionAdapter,
        user_id: &UserId,
    ) -> Result<(), Error> {
        self.repository
            .mark_email_verified(transaction, user_id)
            .await
    }
}
