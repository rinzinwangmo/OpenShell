// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stand-in for an authorization server: create an issuer key and mint
//! delegation grants for local testing. In production, grants come from the
//! organization's authorization server or token-exchange service.

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::{Parser, Subcommand};
use openshell_supervisor_middleware_delegated_biometric_guard::grant::{
    Actor, GrantClaims, generate_issuer_key, now, sign,
};

#[derive(Debug, Parser)]
#[command(about = "Create issuer keys and mint delegation grants for local testing")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write a new Ed25519 issuer private key and print its public key.
    Keygen {
        /// File to write the base64 PKCS#8 private key to.
        #[arg(long, default_value = "issuer.key")]
        out: PathBuf,
    },
    /// Mint a grant with the issuer private key.
    Mint {
        #[arg(long, default_value = "issuer.key")]
        key: PathBuf,
        #[arg(long)]
        issuer: String,
        /// Human principal (use a pseudonymous id).
        #[arg(long)]
        principal: String,
        /// OpenShell sandbox id the grant is bound to.
        #[arg(long)]
        sandbox: String,
        /// Destination host.
        #[arg(long)]
        audience: String,
        /// Modalities to allow, for example `face` or `face,voice`.
        #[arg(long, value_delimiter = ',')]
        modalities: Vec<String>,
        #[arg(long)]
        purpose: String,
        /// Lifetime in seconds.
        #[arg(long, default_value_t = 300)]
        ttl: u64,
        /// Delegation id; generated when omitted.
        #[arg(long)]
        id: Option<String>,
        /// Parent delegation id, for re-delegation.
        #[arg(long)]
        parent: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Keygen { out } => {
            let (der, public) = generate_issuer_key();
            std::fs::write(&out, STANDARD.encode(der))?;
            println!("private key written to {}", out.display());
            println!("issuer_public_key: {public}");
        }
        Command::Mint {
            key,
            issuer,
            principal,
            sandbox,
            audience,
            modalities,
            purpose,
            ttl,
            id,
            parent,
        } => {
            let der = STANDARD.decode(std::fs::read_to_string(key)?.trim())?;
            let now = now();
            let claims = GrantClaims {
                iss: issuer,
                sub: principal,
                aud: audience.to_ascii_lowercase(),
                act: Some(Actor { sub: sandbox }),
                azp: None,
                scope: modalities
                    .iter()
                    .map(|modality| format!("biometric:{}", modality.trim()))
                    .collect::<Vec<_>>()
                    .join(" "),
                purpose,
                jti: id.unwrap_or_else(|| format!("dlg-{:016x}", rand::random::<u64>())),
                parent_jti: parent,
                iat: now,
                exp: now + ttl,
            };
            println!("{}", sign(&claims, &der)?);
        }
    }
    Ok(())
}
