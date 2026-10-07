// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use clap::Parser;
use openshell_supervisor_middleware_delegated_biometric_guard::{MANIFEST_NAME, serve_addr};

#[derive(Debug, Parser)]
#[command(about = "Run the delegated biometric guard supervisor middleware")]
struct Cli {
    /// Address on which to serve plaintext gRPC.
    #[arg(long, default_value = "127.0.0.1:50061")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    println!("serving {MANIFEST_NAME} on http://{}", cli.bind);
    serve_addr(cli.bind).await?;
    Ok(())
}
