// SPDX-License-Identifier: Apache-2.0

use cpex_parity_harness::spec::HookRenames;
use cpex_parity_harness::{default_root, load_hook_renames, validate_hook_table};

#[test]
fn every_captured_hook_has_one_row_and_every_ppe_hook_is_accounted_for() {
    let root = default_root();
    validate_hook_table(&root, &load_hook_renames(&root).unwrap()).unwrap();
}

#[test]
fn missing_ambiguous_and_wrong_rows_fail_validation() {
    let root = default_root();
    let mut table = load_hook_renames(&root).unwrap();
    table.unchanged.retain(|name| name != "cmf.tool_pre_invoke");
    assert!(
        validate_hook_table(&root, &table)
            .unwrap_err()
            .contains("no rename row")
    );

    let mut table = load_hook_renames(&root).unwrap();
    table.unchanged.push("cmf.tool_pre_invoke".into());
    assert!(table.validate([]).unwrap_err().contains("more than one"));

    let mut table = load_hook_renames(&root).unwrap();
    table
        .renames
        .insert("tool_pre_invoke".into(), "cmf.tool_post_invoke".into());
    assert!(
        table
            .validate([])
            .unwrap_err()
            .contains("expected hook rename")
    );

    let mut table = load_hook_renames(&root).unwrap();
    table.unchanged.retain(|name| name != "cmf.tool_pre_invoke");
    table
        .renames
        .insert("cmf.tool_pre_invoke".into(), "cmf.tool_post_invoke".into());
    assert!(
        table
            .validate([])
            .unwrap_err()
            .contains("unexpected hook rename")
    );

    let mut table = load_hook_renames(&root).unwrap();
    table.unchanged.retain(|name| name != "cmf.llm_input");
    assert!(
        table
            .validate([])
            .unwrap_err()
            .contains("no target or unused row")
    );
    table.unused.push("cmf.llm_input".into());
    table.validate([]).unwrap();
}

#[test]
fn duplicate_yaml_rename_sources_are_rejected() {
    let yaml = "renames:\n  tool_pre_invoke: cmf.tool_pre_invoke\n  tool_pre_invoke: cmf.tool_post_invoke\n";
    assert!(
        serde_yaml::from_str::<HookRenames>(yaml)
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );
}
