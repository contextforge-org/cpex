// Location: ./bindings/python/src/builtins.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Register the bundled APL plugin factories and the APL config visitor on a
// `PluginManager`. Must be called on the **same `Arc`** that will later be
// passed to `load_config_yaml` so the APL visitor's `Weak<PluginManager>`
// upgrades correctly during load.
//
// Delegates to `cpex_builtins::install_builtins`, which mirrors the factory
// set shipped by cpex-ffi. Any new builtin added to cpex-builtins is
// automatically included here via the shared feature flags.

use std::sync::Arc;

use cpex_core::manager::PluginManager;

pub fn register_builtin_factories(manager: &Arc<PluginManager>) {
    cpex_builtins::install_builtins(manager);
}
