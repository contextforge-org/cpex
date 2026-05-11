// Location: ./crates/cpex-core/src/hooks/adapter.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// TypedHandlerAdapter — bridges typed HookHandler<H> to the
// type-erased AnyHookHandler.
//
// This is framework plumbing that plugin authors never see. When a
// plugin is registered via `manager.register_handler::<H, P>()`, the
// manager creates a TypedHandlerAdapter internally. The adapter
// translates between Box<dyn PluginPayload> (what the executor passes)
// and the concrete payload type (what the handler expects), and awaits
// the typed handler's future before re-erasing the result.
//
// `HookHandler<H>` is async-by-default (native AFIT). Plugins that
// don't await anything still write `async fn handle(...)`; the
// compiler emits a trivially-ready future that LLVM inlines, so the
// `.await` here is a no-op for sync-style plugins.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::context::PluginContext;
use crate::error::PluginError;
use crate::executor::erase_result;
use crate::hooks::payload::{Extensions, PluginPayload};
use crate::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use crate::plugin::Plugin;
use crate::registry::AnyHookHandler;

// ---------------------------------------------------------------------------
// Typed Handler Adapter
// ---------------------------------------------------------------------------

/// Adapts a typed `HookHandler<H>` into the type-erased `AnyHookHandler`
/// interface used by the executor.
///
/// Created automatically by `PluginManager::register_handler()`. Plugin
/// authors never instantiate this directly.
///
/// `HookHandler<H>` is async (native AFIT), so the adapter awaits the
/// returned future before re-erasing the result. Plugins that don't
/// `.await` anything compile to a ready future that LLVM inlines, so
/// they pay no observable cost over a plain function call.
///
/// # Type Parameters
///
/// - `H` — the hook type (implements `HookTypeDef`).
/// - `P` — the plugin type (implements `Plugin + HookHandler<H>`).
pub struct TypedHandlerAdapter<H, P>
where
    H: HookTypeDef,
    H::Result: Into<PluginResult<H::Payload>>,
    P: Plugin + HookHandler<H> + 'static,
{
    /// The plugin instance.
    plugin: Arc<P>,

    /// Phantom data to carry the hook type parameter.
    _hook: PhantomData<H>,
}

impl<H, P> TypedHandlerAdapter<H, P>
where
    H: HookTypeDef,
    H::Result: Into<PluginResult<H::Payload>>,
    P: Plugin + HookHandler<H> + 'static,
{
    /// Create a new adapter wrapping the given plugin.
    pub fn new(plugin: Arc<P>) -> Self {
        Self {
            plugin,
            _hook: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<H, P> AnyHookHandler for TypedHandlerAdapter<H, P>
where
    H: HookTypeDef,
    H::Result: Into<PluginResult<H::Payload>>,
    P: Plugin + HookHandler<H> + 'static,
{
    /// Downcast the type-erased payload to the concrete type and call
    /// the plugin's typed `handle()` method, awaiting the returned
    /// future.
    ///
    /// The framework retains ownership of the payload — the handler
    /// receives a borrow (`&H::Payload`) and clones only if it needs
    /// to modify. The result is erased back to `ErasedResultFields`
    /// for the executor.
    ///
    /// For plugins whose body contains no `.await`, the compiler emits
    /// a trivially-ready future and LLVM inlines this `.await` to a
    /// direct return — there is no observable runtime cost over a
    /// plain function call.
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        let typed_ref: &H::Payload =
            payload
                .as_any()
                .downcast_ref::<H::Payload>()
                .ok_or_else(|| PluginError::Config {
                    message: format!(
                        "payload type mismatch for hook '{}': expected {}",
                        H::NAME,
                        std::any::type_name::<H::Payload>()
                    ),
                })?;

        let result = self.plugin.handle(typed_ref, extensions, ctx).await;
        let plugin_result: PluginResult<H::Payload> = result.into();

        Ok(erase_result(plugin_result))
    }

    fn hook_type_name(&self) -> &'static str {
        H::NAME
    }
}
