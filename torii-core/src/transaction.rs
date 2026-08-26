//! Backend-neutral transaction contracts.

use std::{any::Any, future::Future, pin::Pin};

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("operation rejected: {code}: {message}")]
    Rejected { code: String, message: String },
    #[error("transaction operation failed: {0}")]
    Failed(String),
    #[error("invalid credentials")]
    InvalidCredentials,
}

pub trait TransactionAdapter: Send {
    fn backend(&self) -> &'static str;

    fn as_any_mut(&mut self) -> &mut dyn Any {
        panic!("backend-specific transaction downcast is not supported")
    }
}

#[derive(Default)]
pub struct NoopTransactionAdapter;

impl TransactionAdapter for NoopTransactionAdapter {
    fn backend(&self) -> &'static str {
        "unmanaged"
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub trait TransactionOperation<T>: Send {
    fn execute<'a>(
        self: Box<Self>,
        transaction: &'a mut dyn TransactionAdapter,
    ) -> Pin<Box<dyn Future<Output = Result<T, TransactionError>> + Send + 'a>>;
}

#[async_trait]
pub trait TransactionRunner: Send + Sync {
    async fn run<T: Send + 'static>(
        &self,
        operation: Box<dyn TransactionOperation<T>>,
    ) -> Result<T, TransactionError>;
}
