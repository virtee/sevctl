// SPDX-License-Identifier: Apache-2.0

//! Types for adding context to errors that occur during operation
//! while still preserving some of the "backtrace-y" nature that we would
//! normally get with simply panicking.

use std::fmt;

/// This implies an error that _always_ has context associated with it.
pub type Result<T> = std::result::Result<T, Context>;

/// Used to extend `std::result::Result<T, E> such that callers can add
/// additional context to the error case.
pub trait Contextual<T> {
    fn context<S: AsRef<str>>(self, context: S) -> Result<T>;
}

impl<T, E: 'static + std::error::Error> Contextual<T> for std::result::Result<T, E> {
    fn context<S: AsRef<str>>(self, context: S) -> Result<T> {
        self.map_err(|e| Context::new(context.as_ref(), Box::new(e)))
    }
}

/// A wrapper error type used to hold a description of the context surrounding
/// the error.
#[derive(Debug)]
pub struct Context {
    context: String,
    cause: Box<dyn std::error::Error>,
}

impl Context {
    pub fn new(context: &str, cause: Box<dyn std::error::Error>) -> Self {
        Self {
            context: context.into(),
            cause,
        }
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.context)
    }
}

impl std::error::Error for Context {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.cause)
    }
}
