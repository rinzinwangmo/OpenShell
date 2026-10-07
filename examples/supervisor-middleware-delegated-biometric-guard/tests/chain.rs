// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end checks through OpenShell's own supervisor middleware chain
//! runner: registration and `Describe`, `ValidateConfig`, evaluation, header
//! mutation validation, and the platform's handling of operator-run output.

use openshell_core::proto::{SupervisorMiddlewareService, header_mutation};
use openshell_supervisor_middleware::{
    ChainEntry, ChainOutcome, ChainRunner, HttpRequestInput, MiddlewareRegistry, OnError,
};
use openshell_supervisor_middleware_delegated_biometric_guard::grant::{
    Actor, GrantClaims, generate_issuer_key, now, sign,
};
use openshell_supervisor_middleware_delegated_biometric_guard::{MAX_PAYLOAD_BYTES, serve};
use prost_types::value::Kind;
use prost_types::{ListValue, Struct, Value};
use serde_json::json;

const HOST: &str = "api.faceverify.example.test";
const SANDBOX: &str = "sbx-7f3a2c";

fn text(value: &str) -> Value {
    Value {
        kind: Some(Kind::StringValue(value.into())),
    }
}

struct Harness {
    runner: ChainRunner,
    entry: ChainEntry,
    issuer_key: Vec<u8>,
}

async fn harness() -> Harness {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(serve(listener));
    let (issuer_key, public) = generate_issuer_key();
    let registry = MiddlewareRegistry::connect_services(
        Vec::new(),
        vec![SupervisorMiddlewareService {
            name: "delegated-biometric-guard".into(),
            grpc_endpoint: format!("http://{address}"),
            max_payload_bytes: MAX_PAYLOAD_BYTES,
            allow_insecure_transport: true,
            ..Default::default()
        }],
    )
    .await
    .expect("OpenShell accepts the service manifest");
    let entry = ChainEntry {
        name: "biometric-egress".into(),
        implementation: "delegated-biometric-guard".into(),
        order: 10,
        config: Struct {
            fields: [
                ("issuer".to_string(), text("https://idp.example.test")),
                ("issuer_public_key".to_string(), text(&public)),
                (
                    "allowed_purposes".to_string(),
                    Value {
                        kind: Some(Kind::ListValue(ListValue {
                            values: vec![text("identity_verification")],
                        })),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        },
        on_error: OnError::FailClosed,
    };
    let runner = ChainRunner::from_registry(registry);
    runner
        .validate_config(&entry.implementation, entry.config.clone())
        .await
        .expect("OpenShell accepts the policy config");
    Harness {
        runner,
        entry,
        issuer_key,
    }
}

impl Harness {
    fn grant(&self, scope: &str) -> String {
        let now = now();
        sign(
            &GrantClaims {
                iss: "https://idp.example.test".into(),
                sub: "principal:3c9e81".into(),
                aud: HOST.into(),
                act: Some(Actor {
                    sub: SANDBOX.into(),
                }),
                azp: None,
                scope: scope.into(),
                purpose: "identity_verification".into(),
                jti: "dlg-5d21".into(),
                parent_jti: None,
                iat: now,
                exp: now + 300,
            },
            &self.issuer_key,
        )
        .unwrap()
    }

    async fn send(&self, grant: Option<String>, body: Vec<u8>) -> ChainOutcome {
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        if let Some(grant) = grant {
            headers.push(("x-agent-delegation".to_string(), grant));
        }
        self.runner
            .evaluate(
                std::slice::from_ref(&self.entry),
                HttpRequestInput {
                    request_id: "req-1".into(),
                    sandbox_id: SANDBOX.into(),
                    sandbox_name: "kyc-agent".into(),
                    workspace: "default".into(),
                    scheme: "https".into(),
                    host: HOST.into(),
                    port: 443,
                    method: "POST".into(),
                    path: "/v1/verify".into(),
                    query: String::new(),
                    headers,
                    connection_nominated_headers: Vec::new(),
                    body,
                },
            )
            .await
            .expect("chain evaluates")
    }
}

fn face_body() -> Vec<u8> {
    json!({"face_embedding": vec![0.0137; 512]})
        .to_string()
        .into_bytes()
}

fn reason_code(outcome: &ChainOutcome) -> Option<String> {
    outcome
        .denial
        .as_ref()
        .and_then(|denial| denial.reason_code.clone())
}

#[tokio::test]
async fn undelegated_biometric_egress_is_denied_with_a_stable_code() {
    let harness = harness().await;
    let outcome = harness.send(None, face_body()).await;
    assert!(!outcome.allowed);
    assert_eq!(
        reason_code(&outcome).as_deref(),
        Some("biometric_delegation_missing")
    );
}

#[tokio::test]
async fn delegated_egress_is_allowed_and_openshell_accepts_the_grant_removal() {
    let harness = harness().await;
    let outcome = harness
        .send(Some(harness.grant("biometric:face")), face_body())
        .await;
    assert!(outcome.allowed);
    assert!(outcome.header_mutations.iter().any(|mutation| matches!(
        &mutation.operation,
        Some(header_mutation::Operation::Remove(remove)) if remove.name == "x-agent-delegation"
    )));
}

#[tokio::test]
async fn scope_is_enforced_per_modality() {
    let harness = harness().await;
    let outcome = harness
        .send(Some(harness.grant("biometric:voice")), face_body())
        .await;
    assert_eq!(
        reason_code(&outcome).as_deref(),
        Some("biometric_delegation_scope")
    );
}

#[tokio::test]
async fn non_biometric_requests_are_unaffected() {
    let harness = harness().await;
    let outcome = harness
        .send(None, br#"{"status":"pending"}"#.to_vec())
        .await;
    assert!(outcome.allowed);
    assert!(outcome.findings.is_empty());
}

/// Documents current platform behavior this example depends on: OpenShell
/// clears operator-run metadata and normalizes finding text, so the verified
/// principal and delegation id do not reach its outputs. Attribution needs a
/// platform-level field. If this test starts failing, the
/// platform has changed and this example should be revisited.
#[tokio::test]
async fn attribution_from_operator_run_middleware_does_not_reach_openshell_outputs() {
    let harness = harness().await;
    let outcome = harness
        .send(Some(harness.grant("biometric:face")), face_body())
        .await;
    assert!(outcome.allowed);
    assert!(outcome.metadata.values().all(|entries| entries.is_empty()));
    assert!(
        outcome
            .findings
            .iter()
            .all(|finding| finding.finding.r#type == "delegated-biometric-guard.finding")
    );
}

#[test]
fn example_policy_is_valid() {
    let policy = openshell_policy::parse_sandbox_policy(include_str!("../policy.yaml"))
        .expect("example policy parses");
    openshell_policy::validate_sandbox_policy(&policy).expect("example policy is valid");
}
