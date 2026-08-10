# torii-client

`torii-client` provides transport-neutral, compile-checked HTTP contracts for
Torii clients. It defines endpoint paths, HTTP methods, request types, and
response types without selecting an HTTP library.

## WASM clients

Enable the `wasm` feature when using the client from a browser-targeted Rust
application:

```toml
[dependencies]
torii-client = { version = "0.5", features = ["wasm"] }
```

Implement `Transport` with the browser HTTP library used by the application:

```rust,ignore
use torii_client::{Client, Endpoint, Method, Transport};

#[async_trait::async_trait(?Send)]
impl Transport for BrowserTransport {
    type Error = BrowserError;

    async fn call<E>(
        &self,
        base_url: &str,
        request: &E::Request,
    ) -> Result<E::Response, Self::Error>
    where
        E: Endpoint,
    {
        // Use E::SPEC.path, E::SPEC.method, and the typed request/response.
        todo!()
    }
}

let client = Client::new(BrowserTransport::new(), "/auth");
let response = client.call(&torii_client::LoginRequest {
    email: "user@example.com".into(),
    password: "password".into(),
}).await?;
```

The `Client::call` method associates each request with its endpoint at compile
time, so the response type is inferred from the request type.
