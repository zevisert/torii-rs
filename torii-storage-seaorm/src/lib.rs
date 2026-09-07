//! SeaORM storage backend for Torii
//!
//! This crate provides a SeaORM-based storage implementation for the Torii authentication framework.
//! SeaORM is a modern async ORM for Rust that provides type-safe database operations and supports
//! multiple database backends including PostgreSQL, MySQL, and SQLite.
//!
//! # Features
//!
//! - **Multi-Database Support**: Works with PostgreSQL, MySQL, and SQLite through SeaORM
//! - **Type-Safe Operations**: Leverages SeaORM's compile-time query validation
//! - **Async/Await**: Fully async database operations with tokio
//! - **Automatic Migrations**: Built-in schema migration management
//! - **User Management**: Store and retrieve user accounts with email verification support
//! - **Session Management**: Handle user sessions with configurable expiration
//! - **Password Authentication**: Secure password hashing and verification
//! - **OAuth Integration**: Store OAuth account connections and tokens
//! - **Passkey Support**: WebAuthn/FIDO2 passkey storage and challenge management
//!
//! # Usage
//!
//! ```rust,no_run
//! use torii_storage_seaorm::SeaORMStorage;
//! use torii_core::UserId;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to database (supports PostgreSQL, MySQL, SQLite)
//!     let storage = SeaORMStorage::connect("sqlite://todos.db?mode=rwc").await?;
//!
//!     // Run migrations to set up the schema
//!     storage.migrate().await?;
//!
//!     // Convert to repository provider and use with Torii
//!     let repositories = std::sync::Arc::new(storage.into_repository_provider());
//!     let torii = torii::Torii::new(repositories);
//!
//!     Ok(())
//! }
//! ```
//!
//! # Repository Provider
//!
//! The crate provides [`SeaORMRepositoryProvider`] which implements the [`RepositoryProvider`] trait
//! from `torii-core`, allowing it to be used directly with the main Torii authentication coordinator.
//!
//! # Database Support
//!
//! This crate can be used with any database backend supported by SeaORM:
//! - **PostgreSQL**: Production-ready with full feature support
//! - **MySQL**: Production-ready with full feature support
//! - **SQLite**: Great for development and smaller deployments
//!
//! # Storage Implementations
//!
//! This crate implements repository patterns for:
//! - User account management and profile storage
//! - Session management with automatic expiration
//! - Password credential storage with secure hashing
//! - OAuth account connections and token management
//! - WebAuthn passkey credentials and challenge handling
//!
//! # Entity Models
//!
//! The crate defines SeaORM entity models for all authentication data:
//! - `User` - User accounts and profile information
//! - `Session` - Active user sessions
//! - `Password` - Hashed password credentials
//! - `OAuthAccount` - Connected OAuth accounts
//! - `Passkey` - WebAuthn passkey credentials
//! - `PasskeyChallenge` - Temporary passkey challenges
//!
//! All entities include appropriate relationships and indexes for optimal performance.

mod entities;
mod migrations;
mod oauth;
mod passkey;
mod session;
mod user;

pub mod repositories;
pub use repositories::SeaORMRepositoryProvider;

impl TransactionRunnerProvider for SeaORMRepositoryProvider {
    type TransactionRunner = SeaORMTransactionRunner;
    fn transaction_runner(&self) -> Self::TransactionRunner {
        SeaORMTransactionRunner::new(self.database_connection())
    }
}

use migrations::Migrator;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction, Statement};
use sea_orm_migration::prelude::*;
use torii_core::{
    TransactionError, TransactionOperation, TransactionRunner, TransactionRunnerProvider,
};

#[derive(Debug, thiserror::Error)]
pub enum SeaORMStorageError {
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
    #[error("User not found")]
    UserNotFound,
}

/// SeaORM storage backend
///
/// This storage backend uses SeaORM to manage database connections and migrations.
/// It provides a `connect` method to create a new storage instance from a database URL.
/// It also provides a `migrate` method to apply pending migrations.
///
/// # Example
///
/// ```rust,no_run
/// use torii_storage_seaorm::SeaORMStorage;
///
/// #[tokio::main]
/// async fn main() {
///     let storage = SeaORMStorage::connect("sqlite://todos.db?mode=rwc").await.unwrap();
///     let _ = storage.migrate().await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct SeaORMStorage {
    pool: DatabaseConnection,
}

/// SeaORM implementation of Torii's transaction adapter.
pub struct SeaORMTransactionAdapter {
    transaction: DatabaseTransaction,
}

impl SeaORMTransactionAdapter {
    pub fn new(transaction: DatabaseTransaction) -> Self {
        Self { transaction }
    }

    pub fn into_inner(self) -> DatabaseTransaction {
        self.transaction
    }

    /// Borrow the active transaction for storage-specific operations.
    pub fn transaction(&self) -> &DatabaseTransaction {
        &self.transaction
    }
}

pub struct SeaORMTransactionRunner {
    connection: DatabaseConnection,
}

impl SeaORMTransactionRunner {
    pub fn new(connection: DatabaseConnection) -> Self {
        Self { connection }
    }
}

#[async_trait::async_trait]
impl TransactionRunner for SeaORMTransactionRunner {
    async fn run<T: Send + 'static>(
        &self,
        operation: Box<dyn TransactionOperation<T>>,
    ) -> Result<T, TransactionError> {
        use sea_orm::TransactionTrait;
        let transaction = self
            .connection
            .begin()
            .await
            .map_err(|e| TransactionError::Failed(e.to_string()))?;
        let mut adapter = SeaORMTransactionAdapter::new(transaction);
        match operation.execute(&mut adapter).await {
            Ok(value) => {
                adapter
                    .into_inner()
                    .commit()
                    .await
                    .map_err(|e| TransactionError::Failed(e.to_string()))?;
                Ok(value)
            }
            Err(error) => {
                let _ = adapter.into_inner().rollback().await;
                Err(error)
            }
        }
    }
}

#[async_trait::async_trait]
impl torii_services::TransactionAdapter for SeaORMTransactionAdapter {
    fn backend(&self) -> &'static str {
        "seaorm"
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl SeaORMTransactionAdapter {
    /// Execute a SeaORM statement in the active transaction.
    pub async fn execute(
        &mut self,
        statement: Statement,
    ) -> Result<sea_orm::ExecResult, torii_services::HookError> {
        self.transaction
            .execute(statement)
            .await
            .map_err(|error| torii_services::HookError::Failed(error.to_string()))
    }
}

impl SeaORMStorage {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
    }

    pub async fn connect(url: &str) -> Result<Self, SeaORMStorageError> {
        let pool = Database::connect(url).await?;
        pool.ping().await?;

        Ok(Self::new(pool))
    }

    pub async fn migrate(&self) -> Result<(), SeaORMStorageError> {
        Migrator::up(&self.pool, None).await.unwrap();

        Ok(())
    }

    /// Create a repository provider from this storage instance
    pub fn into_repository_provider(self) -> SeaORMRepositoryProvider {
        SeaORMRepositoryProvider::new(self.pool)
    }
}
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use sea_orm::Database;
    use torii_core::storage::NewUser;
    use torii_core::{
        TransactionRunner, UserId,
        repositories::{PasswordRepository, UserRepository},
    };
    use torii_services::{
        AfterUserRegistration, BeforeUserRegistration, HookDecision, HookError, HookRegistry,
        RegisterUserOperation, ToriiHook,
    };

    use crate::migrations::Migrator;

    use super::*;
    use torii_core::TransactionAdapter;

    struct RejectingHook;

    #[async_trait]
    impl ToriiHook for RejectingHook {
        async fn before_user_registration(
            &self,
            _context: &mut BeforeUserRegistration,
            _transaction: &mut dyn TransactionAdapter,
        ) -> Result<HookDecision, HookError> {
            Ok(HookDecision::Reject {
                code: "blocked".to_string(),
                message: "registration blocked".to_string(),
            })
        }
    }

    struct FailingAfterHook;

    #[async_trait]
    impl ToriiHook for FailingAfterHook {
        async fn after_user_registration(
            &self,
            _context: &AfterUserRegistration,
            _transaction: &mut dyn TransactionAdapter,
        ) -> Result<(), HookError> {
            Err(HookError::Failed("registration audit failed".to_string()))
        }
    }

    struct MutatingHook;

    #[async_trait]
    impl ToriiHook for MutatingHook {
        async fn before_user_registration(
            &self,
            context: &mut BeforeUserRegistration,
            _transaction: &mut dyn TransactionAdapter,
        ) -> Result<HookDecision, HookError> {
            context.email = "mutated@example.com".to_string();
            context.name = Some("Mutated User".to_string());
            Ok(HookDecision::Continue)
        }
    }

    async fn run_registration_test(
        pool: sea_orm::DatabaseConnection,
        hooks: Arc<HookRegistry>,
        email: &str,
    ) -> Result<torii_core::User, TransactionError> {
        let runner = SeaORMTransactionRunner::new(pool.clone());
        let repositories = Arc::new(repositories::SeaORMRepositoryProvider::new(pool));

        runner
            .run(Box::new(RegisterUserOperation {
                repositories,
                hooks,
                new_user: NewUser {
                    id: UserId::new_random(),
                    email: email.to_string(),
                    name: Some("Original User".to_string()),
                    email_verified_at: None,
                },
                password_hash: "password-hash".to_string(),
            }))
            .await
    }

    #[tokio::test]
    async fn test_migrations_up() {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        let migrations = Migrator::get_pending_migrations(&pool).await.unwrap();
        migrations.iter().for_each(|m| {
            println!("{}: {}", m.name(), m.status());
        });
        Migrator::up(&pool, None).await.unwrap();
        let migrations = Migrator::get_pending_migrations(&pool).await.unwrap();
        migrations.iter().for_each(|m| {
            println!("{}: {}", m.name(), m.status());
        });
    }

    #[tokio::test]
    async fn before_hook_rejection_prevents_user_persistence() {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&pool, None).await.unwrap();
        let hooks = Arc::new(HookRegistry::new());
        hooks.register_sync(Arc::new(RejectingHook));

        let result = run_registration_test(pool.clone(), hooks, "rejected@example.com").await;

        assert!(matches!(result, Err(TransactionError::Rejected { .. })));
        let repository = repositories::SeaORMUserRepository::new(pool);
        assert!(
            repository
                .find_by_email("rejected@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn after_hook_error_rolls_back_persistence() {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&pool, None).await.unwrap();
        let hooks = Arc::new(HookRegistry::new());
        hooks.register_sync(Arc::new(FailingAfterHook));

        let result = run_registration_test(pool.clone(), hooks, "rolled-back@example.com").await;

        assert!(
            matches!(result, Err(TransactionError::Failed(message)) if message == "registration audit failed")
        );
        let user_repository = repositories::SeaORMUserRepository::new(pool.clone());
        assert!(
            user_repository
                .find_by_email("rolled-back@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn before_hook_mutation_reaches_user_and_password_operations() {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&pool, None).await.unwrap();
        let hooks = Arc::new(HookRegistry::new());
        hooks.register_sync(Arc::new(MutatingHook));

        let user = run_registration_test(pool.clone(), hooks, "original@example.com")
            .await
            .unwrap();

        assert_eq!(user.email, "mutated@example.com");
        assert_eq!(user.name.as_deref(), Some("Mutated User"));
        let user_repository = repositories::SeaORMUserRepository::new(pool.clone());
        assert!(
            user_repository
                .find_by_email("original@example.com")
                .await
                .unwrap()
                .is_none()
        );
        let stored_user = user_repository
            .find_by_email("mutated@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_user.name.as_deref(), Some("Mutated User"));
        let password_repository = repositories::SeaORMPasswordRepository::new(pool);
        assert_eq!(
            password_repository
                .get_password_hash(&stored_user.id)
                .await
                .unwrap(),
            Some("password-hash".to_string())
        );
    }
}
