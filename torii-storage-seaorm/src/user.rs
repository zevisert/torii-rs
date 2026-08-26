//! SeaORM user types

use torii_core::{User as ToriiUser, UserId};

use crate::entities::user;

impl From<user::Model> for ToriiUser {
    fn from(user: user::Model) -> Self {
        Self {
            id: UserId::new(&user.id),
            name: user.name.to_owned(),
            email: user.email.to_owned(),
            email_verified_at: user.email_verified_at.to_owned(),
            locked_at: user.locked_at.to_owned(),
            created_at: user.created_at.to_owned(),
            updated_at: user.updated_at.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::SeaORMStorage;
    use crate::repositories::SeaORMUserRepository;
    use sea_orm_migration::MigratorTrait;
    use torii_core::repositories::UserRepository;
    use torii_core::{UserId, storage::NewUser};

    async fn setup_test_storage() -> SeaORMStorage {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();

        SeaORMStorage::new(db)
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_create_user() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .name("Test User".to_string())
            .build()
            .unwrap();

        let result = user_repo
            .create(&mut torii_core::NoopTransactionAdapter, new_user)
            .await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name, Some("Test User".to_string()));
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = user_repo
            .create(&mut torii_core::NoopTransactionAdapter, new_user)
            .await
            .unwrap();

        let result = user_repo.find_by_id(&created_user.id).await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user_not_found() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let user_id = UserId::new_random();

        let result = user_repo.find_by_id(&user_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user_by_email() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let _ = user_repo
            .create(&mut torii_core::NoopTransactionAdapter, new_user)
            .await
            .unwrap();

        let result = user_repo.find_by_email("test@example.com").await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user_by_email_not_found() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());

        let result = user_repo.find_by_email("nonexistent@example.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_or_create_user_by_email_existing() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = user_repo
            .create(&mut torii_core::NoopTransactionAdapter, new_user)
            .await
            .unwrap();

        let result = user_repo.find_or_create_by_email("test@example.com").await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.id, created_user.id);
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_or_create_user_by_email_new() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());

        let result = user_repo.find_or_create_by_email("new@example.com").await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.email, "new@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_delete_user() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = user_repo
            .create(&mut torii_core::NoopTransactionAdapter, new_user)
            .await
            .unwrap();

        let result = user_repo
            .delete(&mut torii_core::NoopTransactionAdapter, &created_user.id)
            .await;
        assert!(result.is_ok());

        // Verify user is deleted
        let result = user_repo.find_by_id(&created_user.id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_set_user_email_verified() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = user_repo
            .create(&mut torii_core::NoopTransactionAdapter, new_user)
            .await
            .unwrap();

        let result = user_repo
            .mark_email_verified(&mut torii_core::NoopTransactionAdapter, &created_user.id)
            .await;
        assert!(result.is_ok());

        // Verify email is marked as verified
        let result = user_repo.find_by_id(&created_user.id).await;
        assert!(result.is_ok());

        let user = result.unwrap().unwrap();
        assert!(user.email_verified_at.is_some());
    }
}
