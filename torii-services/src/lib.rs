//! Service implementations for the torii project
//!
//! This module contains the service functionality for the torii project.
//!
//! It includes the services that implement the repository architecture.
//!
//! The service module is designed to be used as a dependency for authentication services and storage backends.
//!

pub mod eventbus;
pub mod hooks;
pub use eventbus::{EventBus, EventPublisher};
pub use hooks::{
    // Security contexts
    AfterAccountLockout,
    AfterAccountUnlock,
    AfterBruteForceCheck,
    AfterBruteForceRecord,
    AfterBruteForceReset,
    // Email verification contexts
    AfterEmailVerification,
    AfterLoginFailure,
    // Magic link contexts
    AfterMagicLinkAuthentication,
    // OAuth contexts
    AfterOAuthAccountLink,
    AfterOAuthAccountUnlink,
    AfterOAuthAuthentication,
    // Passkey contexts
    AfterPasskeyAuthentication,
    AfterPasskeyRegistration,
    AfterPasskeyRemoval,
    // Password contexts
    AfterPasswordAuthentication,
    AfterPasswordChange,
    AfterPasswordRegistration,
    AfterPasswordRemoval,
    // Password reset contexts
    AfterPasswordResetCompletion,
    AfterPasswordResetRequest,
    // Session contexts
    AfterSessionCreation,
    AfterSessionDeletion,
    AfterSessionRefresh,
    AfterSessionsClear,
    // User contexts
    AfterUserDeletion,
    AfterUserRegistration,
    AfterUserUpdate,
    AuthenticateMagicLinkOperation,
    AuthenticateOAuthOperation,
    AuthenticatePasskeyOperation,
    AuthenticatePasswordOperation,
    BeforeBruteForceCheck,
    BeforeBruteForceRecord,
    BeforeBruteForceReset,
    BeforeEmailVerificationRequest,
    BeforeMagicLinkSend,
    BeforeOAuthAccountLink,
    BeforeOAuthAccountUnlink,
    BeforeOAuthAuthentication,
    BeforePasskeyRegistration,
    BeforePasswordAuthentication,
    BeforePasswordChange,
    BeforePasswordRegistration,
    BeforePasswordResetRequest,
    BeforeSessionCreation,
    BeforeSessionDeletion,
    BeforeSessionsClear,
    BeforeUserDeletion,
    BeforeUserRegistration,
    BeforeUserUpdate,
    BruteForceOutcome,
    ChangePasswordOperation,
    CheckBruteForceOperation,
    ClearSessionsOperation,
    CompleteEmailVerificationOperation,
    CompleteMagicLinkAuthenticationOperation,
    CompleteOAuthAuthenticationOperation,
    CompletePasskeyAuthenticationOperation,
    CompletePasswordChangeOperation,
    CompletePasswordLoginOperation,
    CompletePasswordResetOperation,
    ConsumePkceOperation,
    CreateSessionOperation,
    DeleteSessionOperation,
    DeleteUserOperation,
    GenerateEmailVerificationOperation,
    GenerateMagicLinkOperation,
    // Error and decision types
    HookDecision,
    HookError,
    // Hook trait and registry
    HookRegistry,
    LinkOAuthAccountOperation,
    OAuthAuthenticationResult,
    PasskeyRemovalOutcome,
    PasswordLoginOutcome,
    PasswordRegistrationOutcome,
    PasswordResetOutcome,
    RecordBruteForceOperation,
    RefreshSessionOperation,
    RegisterPasskeyOperation,
    RegisterUserOperation,
    RemovePasskeyOperation,
    RemoveUserPasskeysOperation,
    RequestPasswordResetOperation,
    ResetBruteForceOperation,
    ResetPasswordOperation,
    SessionDeletionOutcome,
    StorePkceOperation,
    ToriiHook,
    UnlinkOAuthAccountOperation,
    VerifyEmailOperation,
};
pub use torii_core::{
    TransactionAdapter, TransactionError, TransactionOperation, TransactionRunner,
};

#[cfg(feature = "postgres")]
pub mod postgres_events;
#[cfg(feature = "postgres")]
pub use postgres_events::PostgresEventTransport;

pub mod services;
pub use services::{
    BruteForceProtectionService, EmailVerificationService, MagicLinkService, OAuthService,
    PasskeyService, PasswordResetService, PasswordService, SessionService, UserService,
};
#[cfg(feature = "mailer")]
pub use services::{MailerService, ToriiMailerService};
