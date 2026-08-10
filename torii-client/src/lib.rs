use serde::{Deserialize, Serialize, de::DeserializeOwned};
pub use torii_core::{Session, User};

#[async_trait::async_trait(?Send)]
pub trait Transport {
    type Error;

    async fn call<E>(
        &self,
        base_url: &str,
        request: &E::Request,
    ) -> Result<E::Response, Self::Error>
    where
        E: Endpoint;
}

#[derive(Clone)]
pub struct Client<T> {
    transport: T,
    base_url: String,
}

impl<T> Client<T> {
    pub fn new(transport: T, base_url: impl Into<String>) -> Self {
        Self {
            transport,
            base_url: base_url.into(),
        }
    }
}

impl<T: Transport> Client<T> {
    pub async fn call<R>(
        &self,
        request: &R,
    ) -> Result<<R::Endpoint as Endpoint>::Response, T::Error>
    where
        R: EndpointRequest,
    {
        self.transport
            .call::<R::Endpoint>(&self.base_url, request)
            .await
    }

    pub async fn call_endpoint<E>(&self, request: &E::Request) -> Result<E::Response, T::Error>
    where
        E: Endpoint,
    {
        self.transport.call::<E>(&self.base_url, request).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyMagicTokenRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResetTokenRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: User,
    pub session: Session,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub user: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub session: Session,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResetTokenResponse {
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// The shared metadata and type pairing for one HTTP endpoint.

#[derive(Debug, Clone, Copy)]
pub struct EndpointSpec<Request, Response> {
    pub path: &'static str,
    pub method: Method,
    _types: std::marker::PhantomData<fn(Request) -> Response>,
}

impl<Request, Response> EndpointSpec<Request, Response> {
    pub const fn new(path: &'static str, method: Method) -> Self {
        Self {
            path,
            method,
            _types: std::marker::PhantomData,
        }
    }
}

/// Describes one JSON HTTP endpoint without choosing an HTTP client.
pub trait Endpoint {
    type Request: Serialize;
    type Response: DeserializeOwned;

    const SPEC: EndpointSpec<Self::Request, Self::Response>;
}

pub trait EndpointRequest: Serialize {
    type Endpoint: Endpoint<Request = Self>;
}

pub mod path {
    pub const HEALTH: &str = "/health";
    pub const SESSION: &str = "/session";
    pub const USER: &str = "/user";
    pub const LOGOUT: &str = "/logout";
    pub const REGISTER: &str = "/register";
    pub const LOGIN: &str = "/login";
    pub const CHANGE_PASSWORD: &str = "/password";
    pub const PASSWORD_RESET: &str = "/password/reset";
    pub const PASSWORD_RESET_REQUEST: &str = "/password/reset/request";
    pub const PASSWORD_RESET_VERIFY: &str = "/password/reset/verify";
    pub const PASSWORD_RESET_CONFIRM: &str = "/password/reset/confirm";
    pub const MAGIC_LINK: &str = "/magic-link";
    pub const MAGIC_LINK_VERIFY: &str = "/magic-link/verify";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Delete,
}

#[macro_export]
macro_rules! define_endpoint {
    ($name:ident, $method:expr, $path:expr, $request:ty, $response:ty) => {
        pub struct $name;

        impl $crate::Endpoint for $name {
            type Request = $request;
            type Response = $response;

            const SPEC: $crate::EndpointSpec<Self::Request, Self::Response> =
                $crate::EndpointSpec::new($path, $method);
        }
    };
}

define_endpoint!(
    HealthEndpoint,
    Method::Get,
    path::HEALTH,
    EmptyRequest,
    HealthResponse
);
define_endpoint!(
    SessionEndpoint,
    Method::Get,
    path::SESSION,
    EmptyRequest,
    SessionResponse
);
define_endpoint!(
    UserEndpoint,
    Method::Get,
    path::USER,
    EmptyRequest,
    UserResponse
);
define_endpoint!(
    LogoutEndpoint,
    Method::Post,
    path::LOGOUT,
    EmptyRequest,
    MessageResponse
);
define_endpoint!(
    RegisterEndpoint,
    Method::Post,
    path::REGISTER,
    RegisterRequest,
    MessageResponse
);
define_endpoint!(
    LoginEndpoint,
    Method::Post,
    path::LOGIN,
    LoginRequest,
    AuthResponse
);
define_endpoint!(
    ChangePasswordEndpoint,
    Method::Post,
    path::CHANGE_PASSWORD,
    ChangePasswordRequest,
    MessageResponse
);
define_endpoint!(
    PasswordResetRequestEndpoint,
    Method::Post,
    path::PASSWORD_RESET_REQUEST,
    PasswordResetRequest,
    PasswordResetResponse
);
define_endpoint!(
    PasswordResetVerifyEndpoint,
    Method::Post,
    path::PASSWORD_RESET_VERIFY,
    VerifyResetTokenRequest,
    VerifyResetTokenResponse
);
define_endpoint!(
    PasswordResetConfirmEndpoint,
    Method::Post,
    path::PASSWORD_RESET_CONFIRM,
    ResetPasswordRequest,
    UserResponse
);
define_endpoint!(
    MagicLinkRequestEndpoint,
    Method::Post,
    path::MAGIC_LINK,
    MagicLinkRequest,
    MagicLinkResponse
);
define_endpoint!(
    MagicLinkVerifyEndpoint,
    Method::Post,
    path::MAGIC_LINK_VERIFY,
    VerifyMagicTokenRequest,
    AuthResponse
);

#[macro_export]
macro_rules! define_endpoint_request {
    ($request:ty, $endpoint:ty) => {
        impl $crate::EndpointRequest for $request {
            type Endpoint = $endpoint;
        }
    };
}
// There can be no
define_endpoint_request!(RegisterRequest, RegisterEndpoint);
define_endpoint_request!(LoginRequest, LoginEndpoint);
define_endpoint_request!(ChangePasswordRequest, ChangePasswordEndpoint);
define_endpoint_request!(PasswordResetRequest, PasswordResetRequestEndpoint);
define_endpoint_request!(VerifyResetTokenRequest, PasswordResetVerifyEndpoint);
define_endpoint_request!(ResetPasswordRequest, PasswordResetConfirmEndpoint);
define_endpoint_request!(MagicLinkRequest, MagicLinkRequestEndpoint);
define_endpoint_request!(VerifyMagicTokenRequest, MagicLinkVerifyEndpoint);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct RecordingTransport {
        calls: Arc<Mutex<Vec<(String, Method, String)>>>,
    }

    #[async_trait::async_trait(?Send)]
    impl Transport for RecordingTransport {
        type Error = String;

        async fn call<E>(
            &self,
            base_url: &str,
            request: &E::Request,
        ) -> Result<E::Response, Self::Error>
        where
            E: Endpoint,
        {
            let body = serde_json::to_string(request).map_err(|error| error.to_string())?;
            self.calls
                .lock()
                .expect("recording transport mutex should not be poisoned")
                .push((base_url.to_string(), E::SPEC.method, body));

            serde_json::from_str(
                r#"{"user":{"id":"user-1","name":null,"email":"user@example.com","email_verified_at":null,"locked_at":null,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"},"session":{"token":"session-1","user_id":"user-1","user_agent":null,"ip_address":null,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","expires_at":"2024-01-02T00:00:00Z"}}"#,
            )
            .map_err(|error| error.to_string())
        }
    }

    #[test]
    fn endpoint_specs_expose_shared_route_contract() {
        assert_eq!(HealthEndpoint::SPEC.path, path::HEALTH);
        assert_eq!(HealthEndpoint::SPEC.method, Method::Get);
        assert_eq!(LoginEndpoint::SPEC.path, path::LOGIN);
        assert_eq!(LoginEndpoint::SPEC.method, Method::Post);
        assert_eq!(LogoutEndpoint::SPEC.path, path::LOGOUT);
        assert_eq!(LogoutEndpoint::SPEC.method, Method::Post);
    }

    #[tokio::test]
    async fn client_call_uses_request_endpoint_pairing() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let client = Client::new(
            RecordingTransport {
                calls: calls.clone(),
            },
            "https://example.com/auth",
        );

        let response = client
            .call(&LoginRequest {
                email: "user@example.com".to_string(),
                password: "correct horse battery staple".to_string(),
            })
            .await
            .expect("mock response should decode");

        assert_eq!(response.user.email, "user@example.com");
        let calls = calls
            .lock()
            .expect("recording transport mutex should not be poisoned");
        assert_eq!(
            calls.as_slice(),
            &[(
                "https://example.com/auth".to_string(),
                Method::Post,
                r#"{"email":"user@example.com","password":"correct horse battery staple"}"#
                    .to_string(),
            )]
        );
    }

    #[test]
    fn endpoint_requests_serialize_as_json() {
        let request = PasswordResetRequest {
            email: "user@example.com".to_string(),
        };

        assert_eq!(
            serde_json::to_value(request).expect("request should serialize"),
            serde_json::json!({"email": "user@example.com"})
        );
    }
}
