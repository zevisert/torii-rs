# torii-services

Service implementations for the Torii authentication framework.

This crate contains the Tokio-dependent authentication services and event bus
used by the server-side `torii` crate. Foundational types, storage traits, and
runtime-neutral session providers live in `torii-core`.

## Features

- **User Management**: Core user types and management services
- **Session Management**: Flexible session handling with both opaque and JWT tokens
- **Service Architecture**: Modular services for different authentication methods
- **Event Bus**: Event handler registration and asynchronous event delivery
- **Storage Integration**: Services built on the repository traits from `torii-core`
- **Async/Await**: Tokio-based server-side service implementations
- **Error Handling**: Comprehensive error types with structured error handling

## Core Types

### Users

Users are the foundation of the authentication system. The `User` struct includes:

| Field               | Type               | Description                                       |
| ------------------- | ------------------ | ------------------------------------------------- |
| `id`                | `UserId`           | The unique identifier for the user                |
| `name`              | `Option<String>`   | The display name of the user                      |
| `email`             | `String`           | The email address of the user                     |
| `email_verified_at` | `Option<DateTime>` | The timestamp when the user's email was verified |
| `created_at`        | `DateTime`         | The timestamp when the user was created          |
| `updated_at`        | `DateTime`         | The timestamp when the user was last updated     |

### Sessions

Sessions track user authentication state and can be implemented as either opaque tokens or JWTs:

| Field        | Type             | Description                                            |
| ------------ | ---------------- | ------------------------------------------------------ |
| `token`      | `SessionToken`   | The session token (opaque or JWT)                     |
| `user_id`    | `UserId`         | The unique identifier for the user                     |
| `user_agent` | `Option<String>` | The user agent of the client that created the session |
| `ip_address` | `Option<String>` | The IP address of the client that created the session |
| `created_at` | `DateTime`       | The timestamp when the session was created            |
| `updated_at` | `DateTime`       | The timestamp when the session was last updated       |
| `expires_at` | `DateTime`       | The timestamp when the session expires                |

## Service Architecture

Torii uses a service-oriented architecture with the following core services:

### UserService

Handles user account management:
- User creation and updates
- Email verification
- User deletion
- User retrieval by ID or email

### SessionService

Manages user sessions:
- Session creation with configurable expiration
- Session validation and retrieval
- Session deletion and cleanup
- Multi-device session management

### Authentication Services

Specialized services for different authentication methods:
- `PasswordService` - Password-based authentication
- `OAuthService` - OAuth/OpenID Connect integration
- `PasskeyService` - WebAuthn/FIDO2 passkey authentication
- `MagicLinkService` - Passwordless magic link authentication

## Storage Abstraction

The crate defines storage traits that can be implemented by different backends:

### UserStorage

```rust
#[async_trait]
pub trait UserStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error>;
    async fn update_user(&self, user: &User) -> Result<User, Self::Error>;
    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error>;
    async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), Self::Error>;
}
```

### SessionStorage

```rust
#[async_trait]
pub trait SessionStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_session(&self, session: &Session) -> Result<Session, Self::Error>;
    async fn get_session(&self, token: &SessionToken) -> Result<Option<Session>, Self::Error>;
    async fn update_session(&self, session: &Session) -> Result<Session, Self::Error>;
    async fn delete_session(&self, token: &SessionToken) -> Result<(), Self::Error>;
    async fn delete_user_sessions(&self, user_id: &UserId) -> Result<(), Self::Error>;
}
```

## Repository Provider

The `RepositoryProvider` trait allows storage backends to provide all necessary repositories:

```rust
#[async_trait]
pub trait RepositoryProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn user_repository(&self) -> &dyn UserRepository<Error = Self::Error>;
    fn session_repository(&self) -> &dyn SessionRepository<Error = Self::Error>;
    fn password_repository(&self) -> &dyn PasswordRepository<Error = Self::Error>;
    // ... other repositories

    async fn migrate(&self) -> Result<(), Self::Error>;
    async fn health_check(&self) -> Result<(), Self::Error>;
}
```

## Session Providers

Torii supports two session token types:

### Opaque Sessions

Traditional session tokens stored in the database:
- Random token generation
- Server-side session validation
- Immediate revocation capability
- Requires database lookup for validation

### JWT Sessions

Self-contained JSON Web Tokens:
- Stateless authentication
- Configurable signing algorithms (HS256, HS384, HS512, RS256, etc.)
- Custom claims support
- No database lookup required for validation

## Type Safety

The crate uses newtype patterns for enhanced type safety:

```rust
// Strongly typed IDs prevent mixing different ID types
pub struct UserId(String);
pub struct SessionToken(String);

// Builder patterns for safe construction
let user = User::builder()
    .id(UserId::new("user_123"))
    .email("user@example.com")
    .build()?;
```

## Error Handling

Comprehensive error handling with structured error types:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Authentication error: {0}")]
    Authentication(String),
    #[error("Validation error: {0}")]
    Validation(String),
}
```

## Usage

This crate is typically used indirectly through the main `torii` crate, but can
be used directly for custom server implementations:

```rust
use torii_services::{SessionService, UserService};

// Create services with repository adapters from your storage backend
let user_service = UserService::new(user_repository);
let session_service = SessionService::new(session_provider);

// Use the services
let user = user_service.create_user(&new_user).await?;
let session = session_service.create_session(&user.id, None, None, duration).await?;
```

## Integration

Storage backends like `torii-storage-sqlite`, `torii-storage-postgres`, and `torii-storage-seaorm` implement the traits defined in this crate to provide concrete storage implementations.
