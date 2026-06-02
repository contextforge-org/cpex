pub mod identity_checker;

/// Simplified plugin result for WASM boundary.
///
/// Maps cleanly to both the WIT `plugin-result` variant (Allow / Deny)
/// and the native `PluginResult<P>` struct. Shared plugin functions
/// return this; the caller (native or WASM) converts to their own result type.
#[derive(Debug, Clone)]
pub enum SimplePluginResult {
    Allow,
    Deny { code: String, reason: String },
}
