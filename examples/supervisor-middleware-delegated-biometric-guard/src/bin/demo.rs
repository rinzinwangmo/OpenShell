// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runs the guard as a real gRPC service and drives it through OpenShell's own
//! supervisor middleware chain runner (`openshell-supervisor-middleware`), the
//! same code the sandbox supervisor uses for registration, `Describe`,
//! `ValidateConfig`, evaluation, and header-mutation validation.
//!
//! No container runtime is needed: the demo stands in for the sandbox proxy by
//! handing the chain runner the parsed request the proxy would.

use std::collections::BTreeSet;

use openshell_core::proto::{HttpRequestResult, SupervisorMiddlewareService, header_mutation};
use openshell_supervisor_middleware::{
    ChainEntry, ChainOutcome, ChainRunner, HttpRequestInput, MiddlewareRegistry, OnError,
};
use openshell_supervisor_middleware_delegated_biometric_guard::config::GuardConfig;
use openshell_supervisor_middleware_delegated_biometric_guard::grant::{
    Actor, GrantClaims, generate_issuer_key, now, sign,
};
use openshell_supervisor_middleware_delegated_biometric_guard::guard::{self, RequestView};
use openshell_supervisor_middleware_delegated_biometric_guard::{MAX_PAYLOAD_BYTES, serve};
use prost_types::value::Kind;
use prost_types::{ListValue, Struct, Value};
use serde_json::json;

const REGISTRATION: &str = "delegated-biometric-guard";
const ISSUER: &str = "https://idp.example.test";
const VENDOR: &str = "api.faceverify.example.test";
const SANDBOX: &str = "sbx-7f3a2c";
const GRANT_HEADER: &str = "x-agent-delegation";

fn text(value: &str) -> Value {
    Value {
        kind: Some(Kind::StringValue(value.into())),
    }
}

fn list(values: &[&str]) -> Value {
    Value {
        kind: Some(Kind::ListValue(ListValue {
            values: values.iter().map(|value| text(value)).collect(),
        })),
    }
}

struct Scenario {
    name: &'static str,
    host: &'static str,
    sandbox: &'static str,
    grant: Option<String>,
    body: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. The guard, as an operator-run gRPC service.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(serve(listener));

    // 2. An issuer key, standing in for the organization's authorization server.
    let (issuer_key, issuer_public_key) = generate_issuer_key();

    // 3. Register the service exactly as gateway configuration would.
    let registry = MiddlewareRegistry::connect_services(
        Vec::new(),
        vec![SupervisorMiddlewareService {
            name: REGISTRATION.into(),
            grpc_endpoint: format!("http://{address}"),
            max_payload_bytes: MAX_PAYLOAD_BYTES,
            allow_insecure_transport: true,
            ..Default::default()
        }],
    )
    .await
    .map_err(|error| format!("registration failed: {error:?}"))?;
    let runner = ChainRunner::from_registry(registry);

    // 4. The policy entry from policy.yaml.
    let entry = ChainEntry {
        name: "biometric-egress".into(),
        implementation: REGISTRATION.into(),
        order: 10,
        config: Struct {
            fields: [
                ("mode".to_string(), text("enforce")),
                ("grant_header".to_string(), text(GRANT_HEADER)),
                ("issuer".to_string(), text(ISSUER)),
                ("issuer_public_key".to_string(), text(&issuer_public_key)),
                (
                    "allowed_purposes".to_string(),
                    list(&["identity_verification", "fraud_review"]),
                ),
                ("image_hosts".to_string(), list(&[VENDOR])),
            ]
            .into_iter()
            .collect(),
        },
        on_error: OnError::FailClosed,
    };
    runner
        .validate_config(&entry.implementation, entry.config.clone())
        .await
        .map_err(|error| format!("config rejected: {error:?}"))?;
    let config = GuardConfig::parse(Some(&entry.config))?;

    let mint = |sandbox: &str, audience: &str, scope: &str, purpose: &str, ttl: i64| {
        let now = now();
        let claims = GrantClaims {
            iss: ISSUER.into(),
            sub: "principal:3c9e81".into(),
            aud: audience.into(),
            act: Some(Actor {
                sub: sandbox.into(),
            }),
            azp: None,
            scope: scope.into(),
            purpose: purpose.into(),
            jti: "dlg-5d21".into(),
            parent_jti: Some("dlg-root-0a7b".into()),
            iat: now,
            exp: now.saturating_add_signed(ttl),
        };
        sign(&claims, &issuer_key).expect("sign grant")
    };

    let face = json!({"subject_ref": "case-4471", "face_embedding": vec![0.0137; 512]})
        .to_string()
        .into_bytes();
    let fingerprint = {
        use base64::Engine;
        let mut record = b"FMR\0 20\0".to_vec();
        record.extend_from_slice(&[0u8; 48]);
        json!({"subject_ref": "case-4471",
               "templates": [base64::engine::general_purpose::STANDARD.encode(record)]})
        .to_string()
        .into_bytes()
    };

    let scenarios = [
        Scenario {
            name: "ordinary request, no biometric data",
            host: VENDOR,
            sandbox: SANDBOX,
            grant: None,
            body: br#"{"subject_ref":"case-4471","status":"pending"}"#.to_vec(),
        },
        Scenario {
            name: "face embedding, no grant",
            host: VENDOR,
            sandbox: SANDBOX,
            grant: None,
            body: face.clone(),
        },
        Scenario {
            name: "face embedding, valid grant",
            host: VENDOR,
            sandbox: SANDBOX,
            grant: Some(mint(
                SANDBOX,
                VENDOR,
                "biometric:face",
                "identity_verification",
                300,
            )),
            body: face.clone(),
        },
        Scenario {
            name: "same grant replayed from another sandbox",
            host: VENDOR,
            sandbox: "sbx-other",
            grant: Some(mint(
                SANDBOX,
                VENDOR,
                "biometric:face",
                "identity_verification",
                300,
            )),
            body: face.clone(),
        },
        Scenario {
            name: "face grant, sent to a different host",
            host: "api.other-vendor.example.test",
            sandbox: SANDBOX,
            grant: Some(mint(
                SANDBOX,
                VENDOR,
                "biometric:face",
                "identity_verification",
                300,
            )),
            body: face.clone(),
        },
        Scenario {
            name: "face grant, ISO 19794-2 fingerprint sent",
            host: VENDOR,
            sandbox: SANDBOX,
            grant: Some(mint(
                SANDBOX,
                VENDOR,
                "biometric:face",
                "identity_verification",
                300,
            )),
            body: fingerprint,
        },
        Scenario {
            name: "grant for an unapproved purpose",
            host: VENDOR,
            sandbox: SANDBOX,
            grant: Some(mint(SANDBOX, VENDOR, "biometric:face", "ad_targeting", 300)),
            body: face.clone(),
        },
        Scenario {
            name: "expired grant",
            host: VENDOR,
            sandbox: SANDBOX,
            grant: Some(mint(
                SANDBOX,
                VENDOR,
                "biometric:face",
                "identity_verification",
                -600,
            )),
            body: face,
        },
    ];

    println!(
        "Delegated biometric guard, evaluated through OpenShell's supervisor middleware chain runner\n"
    );
    for (index, scenario) in scenarios.iter().enumerate() {
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        if let Some(grant) = &scenario.grant {
            headers.push((GRANT_HEADER.to_string(), grant.clone()));
        }
        let direct_headers = headers.clone();
        let outcome: ChainOutcome = runner
            .evaluate(
                std::slice::from_ref(&entry),
                HttpRequestInput {
                    request_id: format!("req-{index}"),
                    sandbox_id: scenario.sandbox.into(),
                    sandbox_name: "kyc-agent".into(),
                    workspace: "default".into(),
                    scheme: "https".into(),
                    host: scenario.host.into(),
                    port: 443,
                    method: "POST".into(),
                    path: "/v1/verify".into(),
                    query: String::new(),
                    headers,
                    connection_nominated_headers: Vec::new(),
                    body: scenario.body.clone(),
                },
            )
            .await
            .map_err(|error| format!("chain evaluation failed: {error:?}"))?;
        // What the guard itself decided and attributed, before OpenShell
        // applies its rules for operator-run middleware output.
        let direct = guard::evaluate(
            &config,
            &RequestView {
                sandbox_id: scenario.sandbox,
                host: scenario.host,
                headers: &direct_headers,
                body: &scenario.body,
            },
        );
        report(index + 1, scenario, &outcome, &direct);
    }
    Ok(())
}

fn report(number: usize, scenario: &Scenario, outcome: &ChainOutcome, direct: &HttpRequestResult) {
    let decision = if outcome.allowed { "ALLOW" } else { "DENY " };
    let code = outcome
        .denial
        .as_ref()
        .and_then(|denial| denial.reason_code.clone())
        .unwrap_or_default();
    println!("{number}. {}", scenario.name);
    println!("   OpenShell decision: {decision} {code}");

    if !direct.findings.is_empty() {
        let guard_types: Vec<&str> = direct.findings.iter().map(|f| f.r#type.as_str()).collect();
        let platform_types: BTreeSet<&str> = outcome
            .findings
            .iter()
            .map(|finding| finding.finding.r#type.as_str())
            .collect();
        println!("   guard findings:     {}", guard_types.join(", "));
        println!(
            "   in OpenShell audit: {} x{}",
            platform_types.into_iter().collect::<Vec<_>>().join(", "),
            outcome.findings.len()
        );
    }

    let keys = [
        "principal",
        "purpose",
        "delegation_uid",
        "delegation_parent_uid",
        "actor",
    ];
    let attributed: Vec<String> = keys
        .iter()
        .filter_map(|key| {
            direct
                .metadata
                .get(*key)
                .map(|value| format!("{key}={value}"))
        })
        .collect();
    if !attributed.is_empty() {
        println!("   guard attributed:   {}", attributed.join(" "));
        let surviving = outcome
            .metadata
            .get("biometric-egress")
            .map_or(0, |metadata| metadata.len());
        println!(
            "   reaches OpenShell:  {}",
            if surviving == 0 {
                "none of it (operator-run middleware metadata is cleared by design)".to_string()
            } else {
                format!("{surviving} metadata entries")
            }
        );
    }
    if scenario.grant.is_some() && outcome.allowed {
        let stripped = outcome.header_mutations.iter().any(|mutation| {
            matches!(&mutation.operation,
                Some(header_mutation::Operation::Remove(remove)) if remove.name == GRANT_HEADER)
        });
        println!(
            "   grant sent to destination: {}",
            if stripped {
                "no, stripped before forwarding"
            } else {
                "yes"
            }
        );
    }
    println!();
}
