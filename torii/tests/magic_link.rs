#![cfg(all(feature = "magic-link", feature = "sqlite"))]

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use torii::{Event, EventError, EventHandler, HookError, ToriiBuilder, ToriiHook};
use torii_core::TransactionAdapter;
use torii_core::repositories::UserRepository;
use torii_services::{BeforeMagicLinkSend, BeforeSessionCreation};

struct EventCollector {
    events: Arc<tokio::sync::Mutex<Vec<Event>>>,
}

#[async_trait]
impl EventHandler for EventCollector {
    async fn handle_event(&self, event: &Event) -> Result<(), EventError> {
        self.events.lock().await.push(event.clone());
        Ok(())
    }
}

struct FailingMagicLinkHook;

#[async_trait]
impl ToriiHook for FailingMagicLinkHook {
    async fn before_magic_link_send(
        &self,
        _context: &mut BeforeMagicLinkSend,
        _transaction: &mut dyn TransactionAdapter,
    ) -> Result<torii::HookDecision, HookError> {
        Err(HookError::Failed("magic-link hook failed".to_string()))
    }
}

struct ToggleSessionHook {
    fail: Arc<AtomicBool>,
}

#[async_trait]
impl ToriiHook for ToggleSessionHook {
    async fn before_session_creation(
        &self,
        _context: &mut BeforeSessionCreation,
        _transaction: &mut dyn TransactionAdapter,
    ) -> Result<torii::HookDecision, HookError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(HookError::Failed("session hook failed".to_string()))
        } else {
            Ok(torii::HookDecision::Continue)
        }
    }
}

async fn test_torii()
-> Result<torii::Torii<torii::sqlite::SqliteRepositoryProvider>, Box<dyn std::error::Error>> {
    Ok(ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await?
        .apply_migrations(true)
        .build()
        .await?)
}

#[tokio::test]
#[ignore = "SQLite token repository is not yet implemented"]
async fn composite_magic_link_auth_creates_session_and_expected_events()
-> Result<(), Box<dyn std::error::Error>> {
    let torii = test_torii().await?;
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    torii
        .event_bus()
        .register(Arc::new(EventCollector {
            events: events.clone(),
        }))
        .await;

    let email = "composite-magic-link@example.com";
    let magic_token = torii.magic_link().generate_token(email).await?;
    let token = magic_token.token().expect("generated token");

    let (user, session) = torii
        .magic_link()
        .authenticate(
            token,
            Some("integration-test".to_string()),
            Some("127.0.0.1".to_string()),
        )
        .await?;

    assert_eq!(user.email, email);
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.user_agent.as_deref(), Some("integration-test"));
    assert_eq!(session.ip_address.as_deref(), Some("127.0.0.1"));
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
        Event::UserCreated(created) if created.id == user.id && created.email == email
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MagicLinkAuthenticated(user_id) if *user_id == user.id
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        Event::SessionCreated(user_id, created)
            if *user_id == user.id && created.token == session.token
    )));
    Ok(())
}

#[tokio::test]
#[ignore = "SQLite token repository is not yet implemented"]
async fn magic_link_token_is_single_use() -> Result<(), Box<dyn std::error::Error>> {
    let torii = test_torii().await?;
    let magic_token = torii
        .magic_link()
        .generate_token("single-use@example.com")
        .await?;
    let token = magic_token.token().expect("generated token");

    torii.magic_link().authenticate(token, None, None).await?;
    assert!(
        torii
            .magic_link()
            .authenticate(token, None, None)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn magic_link_hook_failure_rolls_back_and_emits_no_events()
-> Result<(), Box<dyn std::error::Error>> {
    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await?
        .register_hook(Arc::new(FailingMagicLinkHook))
        .apply_migrations(true)
        .build()
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
            .magic_link()
            .generate_token("rolled-back-magic-link@example.com")
            .await
            .is_err()
    );
    assert!(events.lock().await.is_empty());
    assert!(
        torii
            .repositories()
            .user_repository()
            .find_by_email("rolled-back-magic-link@example.com")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "SQLite token repository is not yet implemented"]
async fn session_hook_failure_rolls_back_token_and_emits_no_auth_events()
-> Result<(), Box<dyn std::error::Error>> {
    let torii = test_torii().await?;
    let fail = Arc::new(AtomicBool::new(false));
    torii
        .hooks()
        .register(Arc::new(ToggleSessionHook { fail: fail.clone() }))
        .await;
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    torii
        .event_bus()
        .register(Arc::new(EventCollector {
            events: events.clone(),
        }))
        .await;

    let magic_token = torii
        .magic_link()
        .generate_token("session-hook@example.com")
        .await?;
    let token = magic_token.token().expect("generated token");
    events.lock().await.clear();
    fail.store(true, Ordering::SeqCst);

    assert!(
        torii
            .magic_link()
            .authenticate(token, None, None)
            .await
            .is_err()
    );
    assert!(events.lock().await.is_empty());

    fail.store(false, Ordering::SeqCst);
    let (user, session) = torii.magic_link().authenticate(token, None, None).await?;
    assert_eq!(session.user_id, user.id);
    Ok(())
}
