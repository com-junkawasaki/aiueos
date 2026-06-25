//! aiueos error type. Kept dependency-free (no `thiserror`) so the semantic core
//! stays light.

use std::fmt;

#[derive(Debug)]
pub enum AiueError {
    Io(std::io::Error),
    /// EDN failed to parse.
    Edn(String),
    /// A manifest/policy/schema was structurally invalid (well-formed EDN, wrong
    /// shape).
    Schema(String),
    /// Policy / capability-linking verification failed. Carries every violation
    /// so the caller can show all of them at once.
    Denied(Vec<crate::policy::Violation>),
    /// Safe-kotoba subset checker rejected the source.
    Unsafe(Vec<String>),
    /// CLJ→wasm compilation failed (kototama).
    Compile(String),
    /// wasm execution failed (wasmtime).
    Run(String),
}

pub type Result<T> = std::result::Result<T, AiueError>;

impl fmt::Display for AiueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AiueError::Io(e) => write!(f, "io error: {e}"),
            AiueError::Edn(e) => write!(f, "edn parse error: {e}"),
            AiueError::Schema(e) => write!(f, "schema error: {e}"),
            AiueError::Denied(vs) => {
                writeln!(f, "policy denied ({} violation(s)):", vs.len())?;
                for v in vs {
                    writeln!(f, "  ✗ [{}] {}: {}", v.kind.label(), v.component, v.message)?;
                }
                Ok(())
            }
            AiueError::Unsafe(rs) => {
                writeln!(f, "safe-kotoba subset rejected source ({}):", rs.len())?;
                for r in rs {
                    writeln!(f, "  ✗ {r}")?;
                }
                Ok(())
            }
            AiueError::Compile(e) => write!(f, "compile error: {e}"),
            AiueError::Run(e) => write!(f, "run error: {e}"),
        }
    }
}

impl std::error::Error for AiueError {}

impl From<std::io::Error> for AiueError {
    fn from(e: std::io::Error) -> Self {
        AiueError::Io(e)
    }
}

impl From<kotoba_edn::ParseError> for AiueError {
    fn from(e: kotoba_edn::ParseError) -> Self {
        AiueError::Edn(e.to_string())
    }
}
