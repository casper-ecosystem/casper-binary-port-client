/// The `communication` module provides both shared and platform-specific functionalities
/// for managing communication processes.
///
/// # Modules
/// - [`common`]: Contains utilities and shared logic that are used across all target architectures.
pub mod common;

/// - [`wasm32`]: Contains WebAssembly-specific (`wasm32` target) communication utilities,
///               available only when compiled for WebAssembly.
#[cfg(target_arch = "wasm32")]
pub mod wasm32;
