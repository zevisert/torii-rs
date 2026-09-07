# Lifecycle Hooks

Torii lifecycle hooks let an application inspect, modify, approve, or reject
authentication operations without replacing Torii's public APIs or Axum
routes. Hooks are registered on the builder and run by the transactional
operation that owns the lifecycle.

## Registering Hooks

Hooks are registered in builder order:

```rust,no_run
use std::sync::Arc;
use torii::{Torii, ToriiBuilder};
use torii_services::{HookDecision, ToriiHook, BeforeUserRegistration, AfterPasswordResetRequest};

struct TenantPolicy;

#[async_trait::async_trait]
impl ToriiHook for TenantPolicy {
    async fn before_user_registration(
        &self,
        context: &mut BeforeUserRegistration,
        _transaction: &mut dyn torii_core::TransactionAdapter,
    ) -> Result<HookDecision, torii_services::HookError> {
        context.email = context.email.trim().to_lowercase();
        Ok(HookDecision::Continue)
    }

    // Other hooks can be implemented in the same or other structs
    async fn after_password_reset_request(
        &self,
        context: &AfterPasswordResetRequest,
        transaction: &mut dyn TransactionAdapter,
    ) -> Result<(), HookError> {
        ...
    }
}

let torii = ToriiBuilder::new(repositories)
    .register_hook(Arc::new(TenantPolicy))
    .build()?;
```

Hooks are executed sequentially in registration order. A before hook may
modify its mutable context or reject the operation. An after hook observes the
completed in-transaction state and may fail according to its configured
failure policy.

## Transaction Boundary

The high-level `Torii` and Axum-facing APIs acquire a provider-owned
transaction runner. The runner begins a transaction, executes the operation,
and commits only if the operation and its hooks succeed:

```text
public Torii API
├──> transaction runner
│    ├──> before hooks
│    ├──> repository/service mutations
│    └──> after hooks
├──> commit
└──> post-commit event emission
```

Every hook receives the same backend-specific `TransactionAdapter` used by the
Torii repositories. A hook can therefore write application-owned audit or
outbox records that commit or roll back with the Torii operation.

Applications normally do not implement a runner. Storage integrations provide
the runner and adapter through `RepositoryProvider`. A storage integration
must downcast the adapter to its own concrete transaction type before executing
backend-specific statements, and must reject an adapter from another backend.

Hooks should not perform external calls that are expected to roll back. Email,
HTTP, and message delivery should happen after commit. For reliable delivery,
see [Reliable external delivery](#reliable-external-delivery).

## Failure Behavior

- A before-hook rejection prevents the mutation and rolls back the transaction.
- Any before- or after-hook failure stops the operation, rolls back the active
  transaction, and returns an error to the caller. None of the operation's
  database changes are committed.
- Hook failures use Torii's normal error model; Axum's existing error mapping
  remains unchanged.
- Hooks should be safe to retry because a transaction may be retried by the
  application or database infrastructure.
- Events are separate from hooks. Events are emitted after commit and cannot
  roll back the operation. Event-delivery failures are logged and do not turn a
  committed operation into a failed operation.

## Available Hooks

### Users

- `before_user_registration`
- `after_user_registration`
- `before_user_update`
- `after_user_update`
- `before_user_deletion`
- `after_user_deletion`

### Sessions

- `before_session_creation`
- `after_session_creation`
- `before_session_deletion`
- `after_session_deletion`
- `before_sessions_clear`
- `after_sessions_clear`
- `after_session_refresh`

### Passwords

- `before_password_registration`
- `after_password_registration`
- `before_password_authentication`
- `after_password_authentication`
- `before_password_change`
- `after_password_change`
- `after_password_removal`

### Password Reset

- `before_password_reset_request`
- `after_password_reset_request`
- `after_password_reset_completion`

### Email Verification

- `before_email_verification_request`
- `after_email_verification`

### Magic Links

- `before_magic_link_send`
- `after_magic_link_authentication`

### OAuth

- `before_oauth_authentication`
- `after_oauth_authentication`
- `before_oauth_account_link`
- `after_oauth_account_link`
- `before_oauth_account_unlink`
- `after_oauth_account_unlink`

### Passkeys

- `before_passkey_registration`
- `after_passkey_registration`
- `after_passkey_authentication`
- `after_passkey_removal`

### Brute-Force Protection

- `before_brute_force_check`
- `after_brute_force_check`
- `before_brute_force_record`
- `after_brute_force_record`
- `before_brute_force_reset`
- `after_brute_force_reset`
- `after_login_failure`
- `after_account_lockout`
- `after_account_unlock`

## Safe Contexts

Contexts expose lifecycle metadata relevant to the operation. They do not
expose passwords, raw reset tokens, raw magic-link tokens, OAuth subjects, or
passkey private material by default.

Use the transaction adapter for application-owned records, not for external
side effects.

## Reliable External Delivery

If an external effect must be reliable, write an application-owned outbox
record inside the hook transaction and process it after commit. The outbox
worker should be independently retryable and idempotent.

## Direct Service Use

Consumers may instantiate `torii-services` services directly. Service methods
that participate in composed operations may require a transaction adapter, but
they do not own the high-level transaction lifecycle.

When services are called directly, consumers are responsible for choosing and
managing the transaction boundary. They are also responsible for dispatching
corresponding events through `EventBus` if they want event notifications. The
high-level `Torii` facade owns post-commit event emission only for operations
invoked through its public APIs.

## Backend Implementations

A storage integration supplies:

1. A concrete `TransactionAdapter` around its native transaction type.
2. A `TransactionRunner` that begins, executes, commits, or rolls back.
3. Transaction-aware repository mutations that downcast and execute against
   the native transaction.
4. Pool-backed implementations for read-only and explicitly maintenance-only
   operations where appropriate.

Token cleanup is intentionally not a hookable lifecycle operation in the
transactional-hooks feature. Expired-token cleanup remains standalone
maintenance work without lifecycle hooks or post-commit events.
