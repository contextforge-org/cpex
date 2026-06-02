mod conversions;

wit_bindgen::generate!({
    path: "wit",
    world: "plugin",
    generate_all,
});

use conversions::{native_result_to_wit, wit_extensions_to_native, wit_payload_to_native};

struct IdentityCheckerPlugin;

impl Guest for IdentityCheckerPlugin {
    fn handle_hook(
        payload: MessagePayload,
        extensions: Extensions,
        _ctx: PluginContext,
    ) -> PluginResult {
        let native_payload = wit_payload_to_native(payload);
        println!("[wasm-plugin] native_payload: {:#?}", native_payload);

        let native_extensions = wit_extensions_to_native(extensions);
        println!("[wasm-plugin] native_extensions: {:#?}", native_extensions);

        let result = cpex_payload::plugins::identity_checker::identity_check(
            &native_payload,
            &native_extensions,
        );
        println!("[wasm-plugin] result: {:?}", result);

        native_result_to_wit(result)
    }
}

export!(IdentityCheckerPlugin);
