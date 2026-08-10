use std::sync::Arc;

use tokio::sync::RwLock;

use torii_core::{
    error::EventError,
    events::{Event, EventHandler},
};

/// Event bus that can emit events and register event handlers
///
/// The event bus is responsible for managing event handlers and emitting events to them.
/// It provides a simple way to register and unregister handlers, and to emit events to all registered handlers.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::Arc;
/// # use torii_core::{User, UserId, error::EventError, events::{Event, EventHandler}};
/// # use torii_services::EventBus;
/// # use async_trait::async_trait;
/// struct MyHandler;
///
/// #[async_trait]
/// impl EventHandler for MyHandler {
///     async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
///         // Handle the event...
///         Ok(())
///     }
/// }
///
/// #[tokio::main]
/// async fn main() {
///     let event_bus = EventBus::default();
///     event_bus.register(Arc::new(MyHandler)).await;
///     event_bus.emit(&Event::UserCreated(User::builder().id(UserId::new("test")).build().unwrap())).await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct EventBus {
    handlers: Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    /// Create a new event bus
    ///
    /// # Examples
    ///
    /// ```
    /// # use torii_services::EventBus;
    /// let event_bus = EventBus::new();
    /// ```
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register an event handler with the event bus
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use torii_core::events::{Event, EventHandler};
    /// # use torii_core::error::EventError;
    /// # use torii_services::EventBus;
    /// # use async_trait::async_trait;
    /// struct MyHandler;
    ///
    /// #[async_trait]
    /// impl EventHandler for MyHandler {
    ///     async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
    ///         // Handle the event...
    ///         Ok(())
    ///     }
    /// }
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let event_bus = EventBus::default();
    /// event_bus.register(Arc::new(MyHandler)).await;
    /// # }
    /// ```
    pub async fn register(&self, handler: Arc<dyn EventHandler>) {
        self.handlers.write().await.push(handler);
    }

    /// Emit an event to all registered handlers
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use torii_core::{User, UserId, events::Event};
    /// # use torii_services::EventBus;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let event_bus = EventBus::default();
    /// event_bus.emit(&Event::UserCreated(User::builder().id(UserId::new("test")).build().unwrap())).await.unwrap();
    /// # }
    /// ```
    pub async fn emit(&self, event: &Event) -> Result<(), EventError> {
        for handler in self.handlers.read().await.iter() {
            handler.handle_event(event).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use torii_core::{
        User, UserId,
        session::{Session, SessionToken},
    };

    struct TestEventHandler {
        called: Arc<AtomicBool>,
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl EventHandler for TestEventHandler {
        async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
            self.called.store(true, Ordering::SeqCst);
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct ErroringEventHandler;

    #[async_trait]
    impl EventHandler for ErroringEventHandler {
        async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
            Err(EventError::BusError("Test error".into()))
        }
    }

    #[tokio::test]
    async fn test_event_bus_empty() {
        let event_bus = EventBus::default();
        let test_user = User::builder()
            .id(UserId::new("test"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        // Should succeed with no handlers
        event_bus
            .emit(&Event::UserCreated(test_user))
            .await
            .expect("Failed to emit event");
    }

    #[tokio::test]
    async fn test_event_bus_multiple_handlers() {
        let event_bus = EventBus::default();
        let called1 = Arc::new(AtomicBool::new(false));
        let count1 = Arc::new(AtomicUsize::new(0));
        let called2 = Arc::new(AtomicBool::new(false));
        let count2 = Arc::new(AtomicUsize::new(0));

        let handler1 = TestEventHandler {
            called: called1.clone(),
            call_count: count1.clone(),
        };
        let handler2 = TestEventHandler {
            called: called2.clone(),
            call_count: count2.clone(),
        };

        event_bus.register(Arc::new(handler1)).await;
        event_bus.register(Arc::new(handler2)).await;

        let test_user = User::builder()
            .id(UserId::new("test"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        // Both handlers should be called
        event_bus
            .emit(&Event::UserCreated(test_user))
            .await
            .expect("Failed to emit event");

        assert!(
            called1.load(Ordering::SeqCst),
            "First handler was not called"
        );
        assert!(
            called2.load(Ordering::SeqCst),
            "Second handler was not called"
        );
        assert_eq!(count1.load(Ordering::SeqCst), 1);
        assert_eq!(count2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_event_bus_error_propagation() {
        let event_bus = EventBus::default();
        event_bus.register(Arc::new(ErroringEventHandler)).await;

        let test_user = User::builder()
            .id(UserId::new("test"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        // Should propagate error from handler
        let result = event_bus.emit(&Event::UserCreated(test_user)).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EventError::BusError(_)));
    }

    #[tokio::test]
    async fn test_event_bus_all_event_types() {
        let event_bus = EventBus::default();
        let called = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));

        let handler = TestEventHandler {
            called: called.clone(),
            call_count: count.clone(),
        };
        event_bus.register(Arc::new(handler)).await;

        let test_user = User::builder()
            .id(UserId::new("test"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        let test_session = Session::builder()
            .token(SessionToken::new("test"))
            .user_id(test_user.id.clone())
            .build()
            .expect("Failed to build test session");

        // Test all event types
        let events = vec![
            Event::UserCreated(test_user.clone()),
            Event::UserUpdated(test_user.clone()),
            Event::UserDeleted(test_user.id.clone()),
            Event::SessionCreated(test_user.id.clone(), test_session.clone()),
            Event::SessionDeleted(
                test_user.id.clone(),
                test_session.token.clone().expect("token should be present"),
            ),
        ];

        for event in events {
            called.store(false, Ordering::SeqCst);
            event_bus.emit(&event).await.expect("Failed to emit event");
            assert!(called.load(Ordering::SeqCst), "Handler was not called");
        }

        assert_eq!(count.load(Ordering::SeqCst), 5);
    }
}
