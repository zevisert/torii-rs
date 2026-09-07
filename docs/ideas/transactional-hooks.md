# Transactional Hooks

## Problem Statement

How might Torii users influence built-in authentication lifecycles with
validated, mutable, and transactional policy hooks without replacing Torii's
automatically generated Axum endpoints?

## Recommended Direction

Add a builder-configured, immutable hook registry with typed lifecycle methods.
Hooks execute sequentially in registration order and are awaited inside Torii
service operations. Before hooks can inspect, modify, or reject an operation.
After hooks run before the transaction commits and can cause a rollback when
their configured failure policy is fatal.

The hook trait should include a backend-specific transaction adapter supplied by
the application. Torii already requires applications to choose a
`torii-storage-*` crate, so hook implementations and application SQL may be
backend-specific as well. This gives a hook access to the same transaction
Torii uses for the authentication mutation, allowing application-owned audit
records and transactional outbox rows to commit or roll back atomically with
Torii state.

Events remain a separate, post-commit notification mechanism. Torii emits an
event only after a successful commit, and event delivery remains best-effort.
Hooks provide lifecycle control and transactional guarantees; events provide
notification and cross-replica fanout.

### Event Ownership

The high-level `Torii` API owns event dispatch for operations executed through
its provider-owned transaction runners. Services in `torii-services` may also
be instantiated and called directly by consumers, but direct service calls do
not participate in the high-level event ownership boundary. Consumers using
services directly are responsible for dispatching their own corresponding
events through the configured `EventBus` if they want event notifications.
This avoids duplicate delivery while keeping the service crates composable.

## Proposed Contract

```rust
#[async_trait]
pub trait ToriiHook: Send + Sync {
    async fn before_user_registration(
        &self,
        context: &mut UserRegistrationContext,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn before_magic_link_send(
        &self,
        context: &mut MagicLinkSendContext,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<HookDecision, HookError> {
        Ok(HookDecision::Continue)
    }

    async fn after_account_lockout(
        &self,
        context: &AfterAccountLockoutContext,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        Ok(())
    }
}
```

`TransactionAdapter` is implemented by each storage integration. It should be
minimal and expose only parameterized statement execution plus backend
identity:

```rust
#[async_trait]
pub trait TransactionAdapter: Send {
    async fn execute(
        &mut self,
        statement: sea_orm::Statement,
    ) -> Result<sea_orm::ExecResult, HookError>;

    fn backend(&self) -> sea_orm::DbBackend;
}
```

The adapter deliberately does not define outbox, audit, or provisioning
helpers. Those patterns belong to applications. Portable hook registration is
supported, but SQL inside a hook may intentionally be specific to the
application's selected backend.

```rust
pub enum HookDecision {
    Continue,
    Reject {
        code: &'static str,
        message: String,
    },
}
```

Hook contexts should be typed and mutable where modification is supported.
They must not expose passwords, raw reset tokens, magic-link tokens, OAuth
subjects, or passkey private material by default.

## Key Assumptions to Validate

- [ ] Each supported storage backend can expose a transaction adapter that can
      be shared by Torii repositories and application hook writes.
- [ ] Repository/provider APIs can carry a transaction context while retaining
      the storage-specific architecture Torii already exposes.
- [ ] An after-hook failure can be mapped to a stable Torii error while
      accurately communicating that the operation was rolled back.
- [ ] Application-owned transactional outbox rows can be written through the
      adapter and committed atomically with Torii state.
- [ ] Hooks are safe to retry and can make their external side effects
      idempotent.
- [ ] Registration-order execution is sufficient and does not require numeric
      priorities.
- [ ] Builder-only registration is sufficient; hook objects can hold dynamic
      application state through `Arc` and other owned dependencies.

## MVP Scope

- Builder-only hook registration.
- Immutable, sequential hook registry.
- Typed before and after hook contexts.
- Backend-specific transaction adapter trait implemented by each storage
  integration.
- SeaORM transaction adapter support for SQLite, PostgreSQL, and MySQL.
- Before user-registration hook with modification and rejection.
- Before magic-link-send hook with modification and rejection.
- After account-lockout hook.
- After-hook failure rolls back the active transaction.
- Event emission only after successful transaction commit.
- Tests proving before-hook rejection prevents mutation.
- Tests proving before-hook modification reaches the mutation.
- Tests proving after-hook failure rolls back database state.
- Tests proving hook order follows registration order.
- Tests proving events are not emitted after rollback.
- Tests proving an application-owned outbox row commits atomically through the
  supported transaction adapter.

## Not Doing

- Treating expired-token cleanup as a transactional hook operation. Cleanup is
  maintenance work, not an authentication lifecycle, and does not need
  lifecycle hooks or post-commit events in this feature. Its existing
  standalone repository API remains unchanged for now. This scope decision
  should be called out in the eventual transactional-hooks PR description.
- Treating email, HTTP, or other external calls as transactionally
  rollbackable.
- Running hooks inside Axum route handlers.
- Requiring users to replace Torii endpoints.
- Using `EventBus` as the hook mechanism.
- Adding runtime hook registration initially.
- Adding hook priorities before registration order proves insufficient.
- Exposing raw passwords or one-time credentials by default.
- Claiming atomicity for arbitrary application database writes that do not use
  the shared transaction adapter.
- Adding a Torii-owned durable outbox in the first hook implementation.
- Requiring application SQL or hook implementations to be portable across
  database backends.

## Failure Semantics

Before-hook failures prevent the operation from starting or committing.

After-hook failures use a per-hook policy. Fatal is the default: the active
transaction rolls back and the request returns an error. Non-fatal hooks are
awaited, their failures are logged or surfaced through configured observability,
and the operation commits.

External side effects remain non-transactional. Applications that need reliable
external delivery should write an outbox record through the shared transaction
adapter and process it independently.

## Open Questions

- Should `ToriiHook` be generic over a backend transaction type, or should the
  builder expose a backend-specific object-safe adapter?
- Should the adapter's `execute` method use SeaORM's `Statement` directly, or a
  small Torii-owned parameterized statement type?
- Hook failures should convert into the existing normal Torii error model. The
  generated Axum endpoints must preserve their current HTTP response mapping;
  hook execution must not introduce a new public HTTP error contract. Rust
  callers of public Torii APIs may still inspect the underlying hook error
  through the normal error source/context chain.
- Should a hook receive raw magic-link delivery data, or only a safe link and
  delivery metadata?
- How should unsupported storage providers behave while transaction-aware hook
  support is incomplete: reject configuration, or leave the implementation as
  an explicit `todo!()` until the provider is supported?
- Torii does not currently expose a request/correlation ID. Should the hook
  operation context introduce one so application audit and outbox records can
  correlate with the originating request?
