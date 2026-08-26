use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use torii::{Event, EventError, EventHandler, EventPublisher, HookDecision, Torii, ToriiHook};
use torii_core::TransactionAdapter;

#[cfg(feature = "sqlite")]
use torii_services::{
    AfterUserRegistration, BeforePasswordAuthentication, BeforePasswordChange, HookError,
};

#[cfg(feature = "sqlite")]
struct FailingRegistrationHook;

#[cfg(feature = "sqlite")]
#[async_trait]
impl ToriiHook for FailingRegistrationHook {
    async fn after_user_registration(
        &self,
        _context: &AfterUserRegistration,
        _transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Err(HookError::Failed("registration hook failed".to_string()))
    }
}

#[cfg(feature = "sqlite")]
struct FailingLoginHook;

#[cfg(feature = "sqlite")]
#[async_trait]
impl ToriiHook for FailingLoginHook {
    async fn before_password_authentication(
        &self,
        _context: &mut BeforePasswordAuthentication,
        _transaction: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Err(HookError::Failed("login hook failed".to_string()))
    }
}

#[cfg(feature = "sqlite")]
struct FailingPasswordChangeHook;

#[cfg(feature = "sqlite")]
#[async_trait]
impl ToriiHook for FailingPasswordChangeHook {
    async fn before_password_change(
        &self,
        _context: &mut BeforePasswordChange,
        _transaction: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Err(HookError::Failed("password change hook failed".to_string()))
    }
}

#[cfg(feature = "sqlite")]
struct CountingHandler {
    calls: Arc<AtomicUsize>,
    fail: bool,
}

#[cfg(feature = "sqlite")]
struct EventCollector {
    events: Arc<tokio::sync::Mutex<Vec<Event>>>,
}

#[cfg(feature = "sqlite")]
#[async_trait]
impl EventHandler for EventCollector {
    async fn handle_event(&self, event: &Event) -> Result<(), EventError> {
        self.events.lock().await.push(event.clone());
        Ok(())
    }
}

#[cfg(feature = "sqlite")]
#[async_trait]
impl EventHandler for CountingHandler {
    async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(EventError::BusError("handler failed".to_string()))
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "sqlite")]
struct FailingPublisher {
    calls: Arc<AtomicUsize>,
}

#[cfg(feature = "sqlite")]
#[async_trait]
impl EventPublisher for FailingPublisher {
    async fn publish(
        &self,
        _envelope: &torii_core::events::EventEnvelope,
    ) -> Result<(), EventError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(EventError::BusError("publisher failed".to_string()))
    }
}

#[cfg(feature = "sqlite")]
struct PostCommitHandler {
    pool: sqlx::SqlitePool,
    user_present_at_delivery: Arc<tokio::sync::Mutex<Vec<bool>>>,
}

#[cfg(feature = "sqlite")]
#[async_trait]
impl EventHandler for PostCommitHandler {
    async fn handle_event(&self, event: &Event) -> Result<(), EventError> {
        let Event::UserCreated(user) = event else {
            return Ok(());
        };

        let present: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)")
            .bind(&user.email)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| EventError::BusError(error.to_string()))?;
        self.user_present_at_delivery
            .lock()
            .await
            .push(present != 0);
        Ok(())
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_basic_torii_functionality() -> Result<(), Box<dyn std::error::Error>> {
    use torii::sqlite::SqliteRepositoryProvider;

    // Create in-memory SQLite database
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
    let repositories = Arc::new(SqliteRepositoryProvider::new(pool));

    // Create Torii instance
    let torii = Torii::new(repositories);

    // Run migrations
    torii.migrate().await?;

    // Health check
    torii.health_check().await?;

    // Test basic user operations
    let user_id = torii_core::user::UserId::new("test-user");

    // Initially, user should not exist
    let user = torii.get_user(&user_id).await?;
    assert!(user.is_none());

    Ok(())
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn registration_events_are_delivered_after_commit() -> Result<(), Box<dyn std::error::Error>>
{
    use sqlx::sqlite::SqlitePoolOptions;
    use torii::sqlite::SqliteRepositoryProvider;

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let repositories = Arc::new(SqliteRepositoryProvider::new(pool.clone()));
    let torii = Torii::new(repositories);
    torii.migrate().await?;

    let user_present_at_delivery = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    torii
        .event_bus()
        .register(Arc::new(PostCommitHandler {
            pool,
            user_present_at_delivery: user_present_at_delivery.clone(),
        }))
        .await;

    torii
        .password()
        .register("post-commit@example.com", "password123")
        .await?;

    assert_eq!(*user_present_at_delivery.lock().await, vec![true]);
    Ok(())
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn registration_rollback_does_not_emit_events() -> Result<(), Box<dyn std::error::Error>> {
    use torii::ToriiBuilder;
    use torii_core::repositories::UserRepository;

    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await?
        .register_hook(Arc::new(FailingRegistrationHook))
        .apply_migrations(true)
        .build()
        .await?;
    let calls = Arc::new(AtomicUsize::new(0));
    torii
        .event_bus()
        .register(Arc::new(CountingHandler {
            calls: calls.clone(),
            fail: false,
        }))
        .await;

    let result = torii
        .password()
        .register("rolled-back@example.com", "password123")
        .await;

    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        torii
            .repositories()
            .user_repository()
            .find_by_email("rolled-back@example.com")
            .await?
            .is_none()
    );
    Ok(())
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn event_delivery_failures_are_best_effort_for_committed_operations()
-> Result<(), Box<dyn std::error::Error>> {
    use torii::sqlite::SqliteRepositoryProvider;

    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
    let repositories = Arc::new(SqliteRepositoryProvider::new(pool));
    let torii = Torii::new(repositories);
    torii.migrate().await?;

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let publisher_calls = Arc::new(AtomicUsize::new(0));
    torii
        .event_bus()
        .register(Arc::new(CountingHandler {
            calls: handler_calls.clone(),
            fail: true,
        }))
        .await;
    torii
        .event_bus()
        .register_publisher(Arc::new(FailingPublisher {
            calls: publisher_calls.clone(),
        }))
        .await;

    let user = torii
        .password()
        .register("best-effort@example.com", "password123")
        .await?;

    assert_eq!(user.email, "best-effort@example.com");
    assert_eq!(handler_calls.load(Ordering::SeqCst), 2);
    assert_eq!(publisher_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn test_password_authentication() -> Result<(), Box<dyn std::error::Error>> {
    use torii::sqlite::SqliteRepositoryProvider;

    // Create in-memory SQLite database
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
    let repositories = Arc::new(SqliteRepositoryProvider::new(pool));

    // Create Torii instance
    let torii = Torii::new(repositories);

    // Run migrations
    torii.migrate().await?;

    // Register a user
    let user = torii
        .password()
        .register("test@example.com", "password123")
        .await?;
    assert_eq!(user.email, "test@example.com");
    assert!(!user.is_email_verified());

    // Verify the email
    torii.set_user_email_verified(&user.id).await?;

    // Login with correct password
    let (logged_in_user, session) = torii
        .password()
        .authenticate(
            "test@example.com",
            "password123",
            Some("test-agent".to_string()),
            Some("127.0.0.1".to_string()),
        )
        .await?;

    assert_eq!(logged_in_user.id, user.id);
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.user_agent, Some("test-agent".to_string()));

    // Try to login with wrong password
    let result = torii
        .password()
        .authenticate("test@example.com", "wrongpassword", None, None)
        .await;
    assert!(result.is_err());

    Ok(())
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn composite_password_login_creates_session_and_expected_events()
-> Result<(), Box<dyn std::error::Error>> {
    use torii::sqlite::SqliteRepositoryProvider;

    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
    let repositories = Arc::new(SqliteRepositoryProvider::new(pool));
    let torii = Torii::new(repositories);
    torii.migrate().await?;
    let user = torii
        .password()
        .register("composite-login@example.com", "password123")
        .await?;

    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    torii
        .event_bus()
        .register(Arc::new(EventCollector {
            events: events.clone(),
        }))
        .await;

    let (logged_in_user, session) = torii
        .password()
        .authenticate(
            "composite-login@example.com",
            "password123",
            Some("integration-test".to_string()),
            Some("127.0.0.1".to_string()),
        )
        .await?;

    assert_eq!(logged_in_user.id, user.id);
    assert_eq!(session.user_id, user.id);
    assert_eq!(
        torii
            .get_session(session.token.as_ref().expect("session token"))
            .await?
            .user_id,
        user.id
    );
    let events = events.lock().await;
    assert!(events.iter().any(|event| matches!(
        event,
        Event::PasswordAuthenticated(user_id) if *user_id == user.id
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        Event::SessionCreated(user_id, created)
            if *user_id == user.id && created.token == session.token
    )));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::LoginFailed { .. }))
    );
    Ok(())
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn composite_password_login_records_lockout_and_security_events()
-> Result<(), Box<dyn std::error::Error>> {
    use chrono::Duration;
    use sqlx::SqlitePool;
    use torii::sqlite::SqliteRepositoryProvider;
    use torii::{BruteForceProtectionConfig, Torii};

    let pool = SqlitePool::connect("sqlite::memory:").await?;
    let torii = Torii::new(Arc::new(SqliteRepositoryProvider::new(pool)))
        .with_brute_force_protection(BruteForceProtectionConfig {
            max_failed_attempts: 1,
            lockout_period: Duration::minutes(15),
            lockout_duration: Duration::minutes(15),
            ..Default::default()
        });
    torii.migrate().await?;
    let user = torii
        .password()
        .register("composite-lockout@example.com", "password123")
        .await?;
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    torii
        .event_bus()
        .register(Arc::new(EventCollector {
            events: events.clone(),
        }))
        .await;

    for _ in 0..1 {
        assert!(
            torii
                .password()
                .authenticate(
                    "composite-lockout@example.com",
                    "wrong-password",
                    None,
                    Some("127.0.0.2".to_string()),
                )
                .await
                .is_err()
        );
    }

    let status = torii
        .get_lockout_status("composite-lockout@example.com")
        .await?;
    assert_eq!(status.failed_attempts, 1);
    assert!(status.is_locked);
    let events = events.lock().await;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::LoginFailed { .. }))
            .count(),
        1
    );
    assert!(events.iter().any(|event| matches!(
        event,
        Event::AccountLocked {
            email,
            failed_attempts: 1,
            ip_address: Some(ip),
            ..
        } if email == "composite-lockout@example.com" && ip == "127.0.0.2"
    )));
    assert!(!events.iter().any(|event| matches!(
        event,
        Event::PasswordAuthenticated(user_id) if *user_id == user.id
    )));
    Ok(())
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn composite_password_login_hook_failure_rolls_back_without_success_event()
-> Result<(), Box<dyn std::error::Error>> {
    use torii::ToriiBuilder;
    use torii_core::repositories::{SessionRepository, SessionRepositoryProvider};

    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await?
        .register_hook(Arc::new(FailingLoginHook))
        .apply_migrations(true)
        .build()
        .await?;
    let user = torii
        .password()
        .register("composite-login-rollback@example.com", "password123")
        .await?;
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    torii
        .event_bus()
        .register(Arc::new(EventCollector {
            events: events.clone(),
        }))
        .await;

    assert!(
        torii
            .password()
            .authenticate(
                "composite-login-rollback@example.com",
                "password123",
                None,
                None
            )
            .await
            .is_err()
    );
    assert!(
        torii
            .repositories()
            .session()
            .find_by_user_id(&user.id)
            .await?
            .is_empty()
    );
    assert!(!events.lock().await.iter().any(|event| matches!(
        event,
        Event::PasswordAuthenticated(user_id) if *user_id == user.id
    )));
    Ok(())
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn composite_password_change_hook_failure_rolls_back_without_success_event()
-> Result<(), Box<dyn std::error::Error>> {
    use torii::ToriiBuilder;

    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await?
        .register_hook(Arc::new(FailingPasswordChangeHook))
        .apply_migrations(true)
        .build()
        .await?;
    let user = torii
        .password()
        .register("composite-change-rollback@example.com", "password123")
        .await?;
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    torii
        .event_bus()
        .register(Arc::new(EventCollector {
            events: events.clone(),
        }))
        .await;

    assert!(
        torii
            .password()
            .change_password(&user.id, "password123", "new-password123")
            .await
            .is_err()
    );
    assert!(events.lock().await.is_empty());
    Ok(())
}
