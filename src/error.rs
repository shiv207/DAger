use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaggerError {
    #[error("failed to run `cargo metadata`: {0}")]
    CargoMetadata(#[from] cargo_metadata::Error),

    #[error("tree-sitter grammar error: {0}")]
    Grammar(String),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, DaggerError>;
