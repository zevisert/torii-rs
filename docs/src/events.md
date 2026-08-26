# Events

Torii emits authentication and lifecycle events through a per-instance event
bus. Events are post-commit notifications: the database operation is the
authoritative state change, and the event announces that committed change to
trusted server-side handlers.

## Local handlers

Every `Torii` instance creates an event bus by default. Register a handler with
the public bus accessor:

```rust,no_run
use std::sync::Arc;
use async_trait::async_trait;
use torii::{Event, EventError, EventHandler, Torii};

struct AuditHandler;

#[async_trait]
impl EventHandler for AuditHandler {
    async fn handle_event(&self, event: &Event) -> Result<(), EventError> {
        tracing::info!(?event, "Torii authentication event");
        Ok(())
    }
}

torii.event_bus().register(Arc::new(AuditHandler)).await;
```

Handlers are local to the process. Handler failures are logged and do not turn
a successfully committed authentication operation into a failed operation.

## Distributed delivery

For multiple backend replicas, register an `EventPublisher`. Publishers are
storage-independent and can be implemented for an application's message bus:

```rust,no_run
torii.register_event_publisher(Arc::new(my_publisher)).await;
```

The publisher receives an `EventEnvelope` containing an event ID, origin
replica ID, timestamp, and event payload. Event handlers should be idempotent.
Events from concurrently running replicas have no global ordering guarantee.

## PostgreSQL fanout

The `postgres` feature provides `PostgresEventTransport`, an opt-in
PostgreSQL `LISTEN`/`NOTIFY` transport. Create it with the same PostgreSQL
connection pool used by the application and register it on the Torii instance:

```rust,no_run
use std::sync::Arc;
use torii::PostgresEventTransport;

let transport = Arc::new(
    PostgresEventTransport::new(pg_pool, torii.event_bus().clone()).await?
);
torii.register_event_publisher(transport).await;
```

Keep the transport alive for as long as the application should receive remote
events. Shut it down during graceful application shutdown:

```rust,no_run
transport.shutdown().await;
```

The transport reconnects after listener failures:

- Listener connection failures are retried with bounded exponential backoff,
  starting at 100 milliseconds and reaching a maximum of 5 seconds.
- Subscription failures are retried with the same backoff.
- Successful reconnection resets the retry delay.
- Individual notifications are not retried when publication or remote
  dispatch fails.

PostgreSQL notifications are live, non-durable fanout. A replica that is
disconnected while a notification is sent can miss the event. No outbox or
replay mechanism is provided. PostgreSQL event fanout may be used with a
PostgreSQL-backed Torii instance or as a separate coordination channel for a
SQLite- or MySQL-backed instance.

## Delivery semantics

- A database transaction must commit before its events are emitted.
- Handler and publisher delivery failures are caught and logged by `EventBus`;
  they are non-fatal after commit and do not turn the committed operation into
  a failed operation. The `EventBus` methods retain a `Result` return type for
  future bus-level failures.
- Events are best-effort and are not part of the database transaction.
- Events are emitted by the replica that successfully committed the operation.
- Local handlers run only while their process is available.
- PostgreSQL fanout reaches replicas with an active listener connection.
- Disconnected replicas may miss PostgreSQL notifications.
- PostgreSQL listener connections and subscriptions are retried with bounded
  exponential backoff.
- Individual event publication and remote dispatch are not retried.
- Under normal operation, consumers should expect one delivery per configured
  delivery path. Transport ambiguity, application retries, or configuration
  errors can still produce duplicate delivery.
- Every `EventEnvelope` has a stable event ID. Consumers should deduplicate by
  event ID when duplicate side effects would be harmful.
- Events from separate replicas have no global ordering guarantee.
- A composite operation may emit multiple events, one for each committed
  domain transition, in the documented logical order.
- Event payloads do not include passwords, reset tokens, magic-link tokens,
  OAuth subjects, or passkey public-key material.
- `SessionDeleted` may contain a trusted server-side `SessionToken`.

## Event categories

Torii currently covers:

- User creation, update, deletion, and email verification.
- Session creation, deletion, bulk deletion, and refresh.
- Failed logins, account lockout, and account unlock.
- Password registration, authentication, change, removal, and reset.
- OAuth authentication and account linking/unlinking.
- Passkey registration, authentication, and removal.
- Magic-link requests and authentication.
