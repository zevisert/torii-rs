# WASM Clients

Torii separates runtime-neutral authentication types from server services so
Rust browser applications can share the API contract with the server.

## Dependencies

Use `torii-client` with its `wasm` feature in a browser-targeted application:

```toml
[dependencies]
torii-client = { version = "0.5", features = ["wasm"] }
```

The crate does not depend on a specific HTTP implementation. Implement its
`Transport` trait with the browser client used by the application, using
`Endpoint::SPEC.path` and `Endpoint::SPEC.method` to build the request. The
request and response types remain paired at compile time.

This makes the same contracts usable from Dioxus, Yew, or another Rust/WASM
framework while `torii-axum` uses them on the server.
