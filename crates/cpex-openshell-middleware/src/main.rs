// Location: ./crates/cpex-openshell-middleware/src/main.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Xiaokui Shu

//! Entry point for the CPEX OpenShell middleware service.
//!
//! Builds the CPEX runtime once from a bundle file, then serves the
//! `SupervisorMiddleware` gRPC contract an unmodified OpenShell supervisor calls
//! as a remote egress middleware.

use std::net::SocketAddr;

use clap::Parser;
use cpex_openshell_middleware::proto::supervisor_middleware_server::SupervisorMiddlewareServer;
use cpex_openshell_middleware::{runtime, CpexMiddlewareService, GRPC_MESSAGE_BYTES};
use tonic::transport::Server;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "cpex-openshell-middleware",
    about = "CPEX as a remote OpenShell supervisor middleware (gRPC)."
)]
struct Args {
    /// Address to serve the SupervisorMiddleware gRPC contract on.
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: SocketAddr,

    /// Path to the CPEX APL bundle YAML. Also read from CPEX_BUNDLE_PATH.
    #[arg(long, env = "CPEX_BUNDLE_PATH")]
    bundle: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // Build the CPEX runtime once. A bad bundle is fatal — the service must not
    // start without a coherent policy (fail closed).
    let authorizer = runtime::build(&args.bundle).await.map_err(|e| {
        format!("failed to build CPEX runtime from bundle {}: {e}", args.bundle)
    })?;
    info!(bundle = %args.bundle, listen = %args.listen, "CPEX OpenShell middleware ready");

    let service = CpexMiddlewareService::new(authorizer);
    let server = SupervisorMiddlewareServer::new(service)
        .max_decoding_message_size(GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(GRPC_MESSAGE_BYTES);

    Server::builder()
        .add_service(server)
        .serve_with_shutdown(args.listen, async {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutting down");
        })
        .await?;

    Ok(())
}
