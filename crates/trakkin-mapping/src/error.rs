use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct MappingError {
    code: &'static str,
    message: String,
    details: Vec<String>,
}

impl MappingError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: Vec::new(),
        }
    }

    pub(crate) fn with_details(
        code: &'static str,
        message: impl Into<String>,
        details: Vec<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            details,
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn details(&self) -> &[String] {
        &self.details
    }
}
