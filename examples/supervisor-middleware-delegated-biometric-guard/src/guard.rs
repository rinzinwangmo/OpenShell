// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The per-request decision: detect biometric data, verify the delegation
//! grant when there is any, and build an OpenShell `HttpRequestResult`.

use std::collections::{BTreeSet, HashMap};

use openshell_core::proto::{
    Decision, Finding, HeaderMutation, HttpRequestResult, RemoveHeader, header_mutation,
};

use crate::config::{GuardConfig, Mode};
use crate::detect::{self, Detections, Modality};
use crate::grant::{self, GrantCheck, GrantClaims, GrantFailure};

/// The request fields the guard reads.
pub struct RequestView<'a> {
    pub sandbox_id: &'a str,
    pub host: &'a str,
    /// Visible request headers as (name, value), names in any case.
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

#[must_use]
pub fn evaluate(config: &GuardConfig, request: &RequestView<'_>) -> HttpRequestResult {
    let grant_values: Vec<&str> = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(&config.grant_header))
        .map(|(_, value)| value.as_str())
        .collect();

    // The grant is for OpenShell, never for the destination. Strip it from
    // every request that carries one, biometric or not.
    let header_mutations = if grant_values.is_empty() {
        Vec::new()
    } else {
        vec![HeaderMutation {
            operation: Some(header_mutation::Operation::Remove(RemoveHeader {
                name: config.grant_header.clone(),
            })),
        }]
    };

    let host = request.host.to_ascii_lowercase();
    let detections = detect::detect(request.body, config.image_hosts.contains(&host));
    if detections.is_empty() {
        return HttpRequestResult {
            decision: Decision::Allow as i32,
            header_mutations,
            ..Default::default()
        };
    }

    let modalities: BTreeSet<Modality> = detections.keys().copied().collect();
    let verdict = grant::verify(
        config,
        &GrantCheck {
            sandbox_id: request.sandbox_id,
            host: &host,
            grant_values: &grant_values,
            modalities: &modalities,
        },
    );

    let mut findings = modality_findings(&detections);
    let mut metadata = HashMap::from([
        ("modalities".to_string(), join(&modalities)),
        ("mode".to_string(), config.mode.as_str().to_string()),
    ]);

    match verdict {
        Ok(claims) => {
            findings.push(Finding {
                r#type: "delegation.verified".into(),
                label: "biometric egress covered by a verified delegation grant".into(),
                count: 1,
                confidence: "high".into(),
                severity: "informational".into(),
            });
            metadata.extend(delegation_metadata(&claims));
            metadata.insert("decision".into(), "delegated".into());
            HttpRequestResult {
                decision: Decision::Allow as i32,
                header_mutations,
                findings,
                metadata,
                ..Default::default()
            }
        }
        Err(failure) => {
            findings.push(Finding {
                r#type: format!("delegation.{}", failure_suffix(failure)),
                label: failure.label().into(),
                count: 1,
                confidence: "high".into(),
                severity: "high".into(),
            });
            metadata.insert("delegation_failure".into(), failure.reason_code().into());
            match config.mode {
                Mode::Enforce => {
                    metadata.insert("decision".into(), "denied".into());
                    HttpRequestResult {
                        decision: Decision::Deny as i32,
                        reason: failure.label().into(),
                        reason_code: failure.reason_code().into(),
                        findings,
                        metadata,
                        ..Default::default()
                    }
                }
                Mode::Audit => {
                    metadata.insert("decision".into(), "audit_would_deny".into());
                    HttpRequestResult {
                        decision: Decision::Allow as i32,
                        header_mutations,
                        findings,
                        metadata,
                        ..Default::default()
                    }
                }
            }
        }
    }
}

fn modality_findings(detections: &Detections) -> Vec<Finding> {
    detections
        .iter()
        .map(|(modality, hit)| Finding {
            r#type: format!("biometric.{}", modality.as_str()),
            label: format!("{} biometric data in request body", modality.as_str()),
            count: hit.count,
            confidence: hit.confidence.as_str().into(),
            severity: "high".into(),
        })
        .collect()
}

/// Identifiers only: which delegation, from which issuer, for whom, for what.
/// These line up with the OCSF `delegation` object (`uid`, `issuer_uid`,
/// `parent_uid`, `created_time`).
fn delegation_metadata(claims: &GrantClaims) -> Vec<(String, String)> {
    let mut entries = vec![
        ("delegation_uid".to_string(), claims.jti.clone()),
        ("delegation_issuer_uid".to_string(), claims.iss.clone()),
        (
            "delegation_created_time".to_string(),
            claims.iat.to_string(),
        ),
        ("principal".to_string(), claims.sub.clone()),
        (
            "actor".to_string(),
            claims.actor().unwrap_or_default().to_string(),
        ),
        ("purpose".to_string(), claims.purpose.clone()),
    ];
    if let Some(parent) = &claims.parent_jti {
        entries.push(("delegation_parent_uid".to_string(), parent.clone()));
    }
    entries
}

fn failure_suffix(failure: GrantFailure) -> &'static str {
    failure
        .reason_code()
        .strip_prefix("biometric_delegation_")
        .unwrap_or("failed")
}

fn join(modalities: &BTreeSet<Modality>) -> String {
    modalities
        .iter()
        .map(|modality| modality.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::config_struct;
    use crate::grant::{Actor, generate_issuer_key, now, sign};
    use prost_types::Value;
    use prost_types::value::Kind;
    use serde_json::json;

    const HOST: &str = "faces.example.test";
    const SANDBOX: &str = "sbx-7f3a";

    fn setup(mode: &str) -> (GuardConfig, Vec<u8>) {
        let (der, public) = generate_issuer_key();
        let mut config = config_struct(&public);
        config.fields.insert(
            "mode".into(),
            Value {
                kind: Some(Kind::StringValue(mode.into())),
            },
        );
        (GuardConfig::parse(Some(&config)).unwrap(), der)
    }

    fn token(der: &[u8]) -> String {
        let now = now();
        sign(
            &GrantClaims {
                iss: "https://idp.example.test".into(),
                sub: "principal:3c9e".into(),
                aud: HOST.into(),
                act: Some(Actor {
                    sub: SANDBOX.into(),
                }),
                azp: None,
                scope: "biometric:face".into(),
                purpose: "identity_verification".into(),
                jti: "dlg-001".into(),
                parent_jti: Some("dlg-root".into()),
                iat: now,
                exp: now + 300,
            },
            der,
        )
        .unwrap()
    }

    fn run(config: &GuardConfig, headers: &[(String, String)], body: &[u8]) -> HttpRequestResult {
        evaluate(
            config,
            &RequestView {
                sandbox_id: SANDBOX,
                host: HOST,
                headers,
                body,
            },
        )
    }

    fn face_body() -> Vec<u8> {
        json!({"face_embedding": vec![0.02; 512]})
            .to_string()
            .into_bytes()
    }

    #[test]
    fn non_biometric_traffic_passes_untouched() {
        let (config, _) = setup("enforce");
        let result = run(&config, &[], br#"{"q":"hello"}"#);
        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(result.findings.is_empty());
        assert!(result.header_mutations.is_empty());
    }

    #[test]
    fn undelegated_biometric_egress_is_denied_in_enforce_mode() {
        let (config, _) = setup("enforce");
        let result = run(&config, &[], &face_body());
        assert_eq!(result.decision, Decision::Deny as i32);
        assert_eq!(result.reason_code, "biometric_delegation_missing");
        let types: Vec<_> = result.findings.iter().map(|f| f.r#type.as_str()).collect();
        assert_eq!(types, ["biometric.face", "delegation.missing"]);
    }

    #[test]
    fn audit_mode_allows_and_records_the_would_be_denial() {
        let (config, _) = setup("audit");
        let result = run(&config, &[], &face_body());
        assert_eq!(result.decision, Decision::Allow as i32);
        assert_eq!(result.metadata["decision"], "audit_would_deny");
    }

    #[test]
    fn delegated_egress_is_allowed_attributed_and_the_grant_is_stripped() {
        let (config, der) = setup("enforce");
        let headers = vec![("X-Agent-Delegation".to_string(), token(&der))];
        let result = run(&config, &headers, &face_body());
        assert_eq!(result.decision, Decision::Allow as i32);
        assert_eq!(result.metadata["principal"], "principal:3c9e");
        assert_eq!(result.metadata["delegation_uid"], "dlg-001");
        assert_eq!(result.metadata["delegation_parent_uid"], "dlg-root");
        assert_eq!(result.metadata["actor"], SANDBOX);
        assert!(matches!(
            result.header_mutations[0].operation,
            Some(header_mutation::Operation::Remove(ref remove)) if remove.name == "x-agent-delegation"
        ));
    }

    #[test]
    fn findings_and_metadata_never_contain_the_token_or_body() {
        let (config, der) = setup("enforce");
        let grant = token(&der);
        let headers = vec![("x-agent-delegation".to_string(), grant.clone())];
        let result = run(&config, &headers, &face_body());
        let rendered = format!("{:?}{:?}", result.findings, result.metadata);
        assert!(!rendered.contains(&grant));
        assert!(!rendered.contains("0.02"));
    }
}
