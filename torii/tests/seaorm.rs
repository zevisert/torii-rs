//! SeaORM integration tests

#[cfg(feature = "seaorm")]
mod tests {
    use std::sync::Arc;
    use torii::{Torii, seaorm::SeaORMStorage};
    use torii_core::repositories::RepositoryProvider;

    #[cfg(feature = "oauth")]
    use async_trait::async_trait;
    #[cfg(feature = "oauth")]
    use torii::{Event, EventError, EventHandler, HookDecision, ToriiBuilder, ToriiHook};
    #[cfg(feature = "oauth")]
    use torii_services::{BeforeSessionCreation, HookError};

    #[cfg(feature = "oauth")]
    struct OAuthEventCollector {
        events: Arc<tokio::sync::Mutex<Vec<Event>>>,
    }

    #[cfg(feature = "oauth")]
    #[async_trait]
    impl EventHandler for OAuthEventCollector {
        async fn handle_event(&self, event: &Event) -> Result<(), EventError> {
            self.events.lock().await.push(event.clone());
            Ok(())
        }
    }

    #[cfg(feature = "oauth")]
    struct FailingSessionCreationHook;

    #[cfg(feature = "oauth")]
    #[async_trait]
    impl ToriiHook for FailingSessionCreationHook {
        async fn before_session_creation(
            &self,
            _context: &mut BeforeSessionCreation,
            _transaction: &mut dyn torii_core::TransactionAdapter,
        ) -> Result<HookDecision, HookError> {
            Err(HookError::Failed("session hook failed".to_string()))
        }
    }

    #[tokio::test]
    async fn test_seaorm_storage_connection() {
        let storage = SeaORMStorage::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to SeaORM storage");

        storage.migrate().await.expect("Failed to run migrations");
    }

    #[tokio::test]
    async fn test_seaorm_repository_provider_with_torii() {
        let storage = SeaORMStorage::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to SeaORM storage");

        storage.migrate().await.expect("Failed to run migrations");

        let repositories = Arc::new(storage.into_repository_provider());

        // Test migration (should be a no-op since we already migrated)
        repositories.migrate().await.expect("Migration failed");

        // Test health check
        repositories
            .health_check()
            .await
            .expect("Health check failed");

        let torii = Torii::new(repositories);

        // Test basic health check through Torii
        torii.health_check().await.expect("Health check failed");
    }

    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn composite_oauth_authentication_creates_account_session_and_ordered_events() {
        use sea_orm::{ConnectOptions, Database};

        let mut options = ConnectOptions::new(format!(
            "sqlite:///tmp/torii-oauth-success-{}-{}.db?mode=rwc",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        options.max_connections(10);
        let torii = ToriiBuilder::new()
            .with_seaorm_connection(Database::connect(options).await.expect("connect"))
            .apply_migrations(true)
            .build()
            .await
            .expect("build");
        let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        torii
            .event_bus()
            .register(Arc::new(OAuthEventCollector {
                events: events.clone(),
            }))
            .await;

        let (user, session) = torii
            .oauth()
            .authenticate(
                "test-provider",
                "subject-123",
                "oauth-composite@example.com",
                Some("OAuth User".to_string()),
                Some("integration-test".to_string()),
                Some("127.0.0.1".to_string()),
            )
            .await
            .expect("OAuth authentication should succeed");
        let account = torii
            .oauth()
            .get_account("test-provider", "subject-123")
            .await
            .expect("query account")
            .expect("account persisted");
        assert_eq!(account.user_id, user.id);
        assert_eq!(session.user_id, user.id);

        let events = events.lock().await;
        assert_eq!(events.len(), 3);
        assert!(matches!(&events[0], Event::UserCreated(created) if created.id == user.id));
        assert!(
            matches!(&events[1], Event::OAuthAuthenticated { user_id, provider } if *user_id == user.id && provider == "test-provider")
        );
        assert!(
            matches!(&events[2], Event::SessionCreated(user_id, created) if *user_id == user.id && created.token == session.token)
        );
    }

    #[cfg(feature = "oauth")]
    #[tokio::test]
    async fn composite_oauth_authentication_hook_failure_rolls_back_without_events() {
        use sea_orm::{ConnectOptions, Database};
        use torii_core::repositories::{UserRepository, UserRepositoryProvider};

        let mut options = ConnectOptions::new(format!(
            "sqlite:///tmp/torii-oauth-rollback-{}.db?mode=rwc",
            std::process::id()
        ));
        options.max_connections(10);
        let torii = ToriiBuilder::new()
            .with_seaorm_connection(Database::connect(options).await.expect("connect"))
            .register_hook(Arc::new(FailingSessionCreationHook))
            .apply_migrations(true)
            .build()
            .await
            .expect("build");
        let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        torii
            .event_bus()
            .register(Arc::new(OAuthEventCollector {
                events: events.clone(),
            }))
            .await;

        assert!(
            torii
                .oauth()
                .authenticate(
                    "test-provider",
                    "rolled-back-subject",
                    "oauth-rollback@example.com",
                    None,
                    None,
                    None
                )
                .await
                .is_err()
        );
        assert!(events.lock().await.is_empty());
        assert!(
            torii
                .repositories()
                .user()
                .find_by_email("oauth-rollback@example.com")
                .await
                .expect("query user")
                .is_none()
        );
        assert!(
            torii
                .oauth()
                .get_account("test-provider", "rolled-back-subject")
                .await
                .expect("query account")
                .is_none()
        );
    }
}
