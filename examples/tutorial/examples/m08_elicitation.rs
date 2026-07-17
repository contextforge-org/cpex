// Location: ./examples/tutorial/examples/m08_elicitation.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Tutorial module 8, Human in the loop (Elicitation).
//
// Prerequisite: the tutorial IdP must be running.
//   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
//
//   cargo run -p cpex-tutorial --example m08_elicitation
//   cargo run -p cpex-tutorial --example m08_elicitation -- --check
//
// The route suspends an outbound email until the caller's manager
// approves. The first call comes back PENDING with an elicitation id. A
// human approves out of band with a curl to the approval channel this
// binary serves on :8090. The caller then retries with the id and the
// call proceeds. In --check mode the module approves itself so CI can
// exercise the full suspend -> approve -> resume path unattended.
//
// The approval plugin below implements the `elicit` hook. It is backed by
// the harness ApprovalChannel; the same channel is served over HTTP for
// the curl. In production this would be an OIDC CIBA backchannel or a push
// to the approver's phone; the point of this module is CPEX's suspend and
// resume model, not the notification transport.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use cpex::PluginManager;
use cpex_core::elicitation::{
    ElicitationHook, ElicitationOp, ElicitationOutcomeKind, ElicitationPayload,
    ElicitationStatusKind,
};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_sdk::{
    Extensions, HookHandler, Plugin, PluginConfig, PluginContext, PluginError, PluginResult,
};

use cpex_tutorial::approvals::{ApprovalChannel, Status};
use cpex_tutorial::backends;
use cpex_tutorial::idp;
use cpex_tutorial::ui;
use cpex_tutorial::{mediate, Caller, Outcome};

use serde_json::json;

const POLICY: &str = include_str!("../policies/m08.yaml");
const APPROVAL_PORT: u16 = 8090;

/// Turn an approver name into a stable elicitation id, so dispatch and the
/// later check agree on which request they mean.
fn elicitation_id_for(approver: &str) -> String {
    let slug: String = approver
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    format!("elic-{slug}")
}

/// An elicitation plugin backed by the harness approval channel. It
/// implements the three operations the runtime drives: dispatch opens a
/// pending request, check reports its status, validate confirms the
/// approver.
struct ChannelApprover {
    cfg: PluginConfig,
    channel: ApprovalChannel,
}

#[async_trait]
impl Plugin for ChannelApprover {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<ElicitationHook> for ChannelApprover {
    async fn handle(
        &self,
        payload: &ElicitationPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<ElicitationPayload> {
        let mut out = payload.clone();
        match payload.operation() {
            ElicitationOp::Dispatch => {
                let approver = payload.from().to_string();
                let id = elicitation_id_for(&approver);
                self.channel
                    .open(&id, &approver, payload.purpose().unwrap_or("(no purpose)"));
                out.id = Some(id);
                out.status = Some(ElicitationStatusKind::Pending);
                out.approver = Some(approver);
            },
            ElicitationOp::Check => {
                let id = payload.elicitation_id().unwrap_or_default();
                match self.channel.status(id) {
                    Some(Status::Approved) => {
                        out.status = Some(ElicitationStatusKind::Resolved);
                        out.outcome = Some(ElicitationOutcomeKind::Approved);
                    },
                    Some(Status::Denied) => {
                        out.status = Some(ElicitationStatusKind::Resolved);
                        out.outcome = Some(ElicitationOutcomeKind::Denied);
                    },
                    _ => out.status = Some(ElicitationStatusKind::Pending),
                }
            },
            ElicitationOp::Validate => {
                out.valid = Some(true);
                out.approver = Some(payload.from().to_string());
            },
        }
        PluginResult::modify_payload(out)
    }
}

struct ChannelApproverFactory {
    channel: ApprovalChannel,
}

impl PluginFactory for ChannelApproverFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(ChannelApprover {
            cfg: config.clone(),
            channel: self.channel.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "elicit",
                Arc::new(TypedHandlerAdapter::<ElicitationHook, _>::new(plugin)),
            )],
        })
    }
}

#[tokio::main]
async fn main() {
    ui::module_banner("Module 8: Human in the loop (Elicitation)");

    // The approval channel: shared between the elicit plugin (which opens
    // and reads requests) and the HTTP server (which the human curls). The
    // HTTP server is only needed for the interactive curl; --check approves
    // through the channel directly, so it skips the server (and its port).
    let channel = ApprovalChannel::new();
    if !ui::check_mode() {
        channel.serve(APPROVAL_PORT);
    }

    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(
        "approval-channel",
        Box::new(ChannelApproverFactory {
            channel: channel.clone(),
        }),
    );
    cpex::install_builtins(&mgr);
    mgr.load_config_yaml(POLICY)
        .expect("policy m08.yaml should load");
    mgr.initialize().await.expect("initialize");

    let evan = match idp::mint_token("evan", "evan").await {
        Ok(t) => Caller::with_token(t),
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            std::process::exit(1);
        },
    };
    let mut all_passed = true;

    // --- First attempt: the call suspends awaiting approval. ---
    ui::scenario("evan → send_email (first attempt: suspends for manager approval)");
    let outcome = mediate(
        &mgr,
        &evan,
        "send_email",
        json!({ "to": "client@partner.example", "subject": "proposal" }),
        backends::send_email,
    )
    .await;
    ui::print_outcome(&outcome);
    let elicitation_id = match &outcome {
        Outcome::Pending { elicitation_id, .. } => elicitation_id.clone(),
        other => {
            println!("  \x1b[33m! expected PENDING, got {other:?}\x1b[0m");
            ui::finish_check(false);
            return;
        },
    };
    all_passed &= outcome.is_pending();

    // --- A human approves out of band. ---
    println!("  Approve it from another terminal with:");
    println!("    curl -X POST localhost:{APPROVAL_PORT}/approvals/{elicitation_id}/approve\n");
    if ui::check_mode() {
        // CI path: approve ourselves so the resume can proceed unattended.
        channel.resolve(&elicitation_id, true);
        println!("  (--check mode approved it automatically)\n");
    } else {
        // Interactive path: wait for the human to curl an approval.
        print!("  waiting for approval");
        for _ in 0..60 {
            if channel.status(&elicitation_id) == Some(Status::Approved) {
                break;
            }
            print!(".");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        println!();
    }

    // --- Retry with the elicitation id: the approval is resolved, so the
    //     call proceeds. ---
    ui::scenario("evan → send_email (retry with the approval: resumes and runs)");
    let resumed = evan.clone().resuming(&elicitation_id);
    let outcome = mediate(
        &mgr,
        &resumed,
        "send_email",
        json!({ "to": "client@partner.example", "subject": "proposal" }),
        backends::send_email,
    )
    .await;
    ui::print_outcome(&outcome);
    all_passed &= ui::expect(&outcome, true);

    println!("The operation suspended until a human approved, then resumed. The agent could not proceed alone.");
    ui::finish_check(all_passed);
}
