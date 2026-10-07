// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Delegation grants: short-lived EdDSA JWTs, issued outside the sandbox, that
//! record which human principal authorized an agent to send which biometric
//! modalities, to which destination, for which purpose.
//!
//! Claim names follow existing standards so a grant can come from an ordinary
//! authorization server or token-exchange service:
//!
//! | Claim        | Meaning                                                         |
//! |--------------|-----------------------------------------------------------------|
//! | `iss`        | Issuing authority. Must match `config.issuer`.                  |
//! | `sub`        | Human principal on whose behalf the agent acts (pseudonymous).  |
//! | `act.sub`    | The actor: the OpenShell sandbox (RFC 8693 actor claim).        |
//! | `azp`        | Alternative to `act.sub`, as OpenShell's token-exchange flow    |
//! |              | uses it (issue #1987). If both appear they must agree.          |
//! | `aud`        | Destination host the biometric data may be sent to.            |
//! | `scope`      | Space-separated `biometric:<modality>` scopes (RFC 8693/OAuth). |
//! | `purpose`    | Declared purpose; must be in `config.allowed_purposes`.         |
//! | `jti`        | Delegation id (maps to OCSF `delegation.uid`).                  |
//! | `parent_jti` | Optional parent delegation for re-delegation chains.           |
//! | `iat`, `exp` | Issue and expiry times.                                         |

use std::collections::BTreeSet;

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::config::GuardConfig;
use crate::detect::Modality;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub sub: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    pub scope: String,
    pub purpose: String,
    pub jti: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_jti: Option<String>,
    pub iat: u64,
    pub exp: u64,
}

impl GrantClaims {
    #[must_use]
    pub fn scopes(&self) -> BTreeSet<&str> {
        self.scope.split_ascii_whitespace().collect()
    }

    /// The acting sandbox named by `act.sub` or `azp`. `None` when neither is
    /// present or when both are present and disagree.
    #[must_use]
    pub fn actor(&self) -> Option<&str> {
        match (
            self.act.as_ref().map(|act| act.sub.as_str()),
            self.azp.as_deref(),
        ) {
            (Some(act), Some(azp)) if act != azp => None,
            (Some(actor), _) | (None, Some(actor)) if !actor.is_empty() => Some(actor),
            _ => None,
        }
    }
}

/// Why a grant did not cover a request. Each maps to a stable deny code that
/// OpenShell may return to the requesting agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantFailure {
    Missing,
    Ambiguous,
    Invalid,
    Expired,
    Audience,
    Actor,
    Scope,
    Purpose,
    Lifetime,
}

impl GrantFailure {
    #[must_use]
    pub fn reason_code(self) -> &'static str {
        match self {
            GrantFailure::Missing => "biometric_delegation_missing",
            GrantFailure::Ambiguous => "biometric_delegation_ambiguous",
            GrantFailure::Invalid => "biometric_delegation_invalid",
            GrantFailure::Expired => "biometric_delegation_expired",
            GrantFailure::Audience => "biometric_delegation_audience",
            GrantFailure::Actor => "biometric_delegation_actor",
            GrantFailure::Scope => "biometric_delegation_scope",
            GrantFailure::Purpose => "biometric_delegation_purpose",
            GrantFailure::Lifetime => "biometric_delegation_lifetime",
        }
    }

    /// Short, audit-safe finding label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            GrantFailure::Missing => "biometric egress without a delegation grant",
            GrantFailure::Ambiguous => "more than one delegation grant on one request",
            GrantFailure::Invalid => "delegation grant failed signature or issuer checks",
            GrantFailure::Expired => "delegation grant expired or not yet valid",
            GrantFailure::Audience => "delegation grant issued for a different destination",
            GrantFailure::Actor => "delegation grant issued to a different sandbox",
            GrantFailure::Scope => "delegation grant does not cover this biometric modality",
            GrantFailure::Purpose => "delegation grant names a purpose policy does not allow",
            GrantFailure::Lifetime => "delegation grant is valid for longer than policy allows",
        }
    }
}

/// Everything the check needs from the request, taken from fields OpenShell
/// itself populates (sandbox id, admitted host) plus the grant header values.
pub struct GrantCheck<'a> {
    pub sandbox_id: &'a str,
    pub host: &'a str,
    pub grant_values: &'a [&'a str],
    pub modalities: &'a BTreeSet<Modality>,
}

/// Verify the request's delegation grant against policy and the detected
/// modalities.
pub fn verify(config: &GuardConfig, check: &GrantCheck<'_>) -> Result<GrantClaims, GrantFailure> {
    let token = match check.grant_values {
        [] => return Err(GrantFailure::Missing),
        [one] => one.trim(),
        _ => return Err(GrantFailure::Ambiguous),
    };

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = config.clock_skew_seconds;
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[check.host.to_ascii_lowercase()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.validate_nbf = true;

    let claims = jsonwebtoken::decode::<GrantClaims>(token, &config.decoding_key, &validation)
        .map_err(|error| match error.kind() {
            ErrorKind::ExpiredSignature | ErrorKind::ImmatureSignature => GrantFailure::Expired,
            ErrorKind::InvalidAudience => GrantFailure::Audience,
            _ => GrantFailure::Invalid,
        })?
        .claims;

    if claims.sub.is_empty() || claims.jti.is_empty() {
        return Err(GrantFailure::Invalid);
    }
    // A grant is a bearer token within its bounds, so its lifetime is part of
    // the policy, not a suggestion to the issuer.
    if claims.exp.saturating_sub(claims.iat) > config.max_grant_lifetime_seconds {
        return Err(GrantFailure::Lifetime);
    }
    // The sandbox id comes from OpenShell's request context, not from the
    // agent, so a grant copied into another sandbox does not verify there.
    let actor_matches = claims.actor().is_some_and(|actor| {
        actor == check.sandbox_id
            || config
                .sandbox_trust_domain
                .as_deref()
                .is_some_and(|domain| {
                    actor == format!("spiffe://{domain}/openshell/sandbox/{}", check.sandbox_id)
                })
    });
    if !actor_matches {
        return Err(GrantFailure::Actor);
    }
    let scopes = claims.scopes();
    if check
        .modalities
        .iter()
        .any(|modality| !scopes.contains(modality.scope().as_str()))
    {
        return Err(GrantFailure::Scope);
    }
    if !config.allowed_purposes.contains(&claims.purpose) {
        return Err(GrantFailure::Purpose);
    }
    Ok(claims)
}

/// Sign a grant. Used by the `mint-grant` tool, the demo, and tests to stand
/// in for an authorization server.
pub fn sign(claims: &GrantClaims, pkcs8_der: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_ed_der(pkcs8_der))
}

/// A new Ed25519 issuer key pair: PKCS#8 DER private key and the base64url
/// public key (the JWK `x` value) to put in policy.
#[must_use]
pub fn generate_issuer_key() -> (Vec<u8>, String) {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;

    let signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let der = signing
        .to_pkcs8_der()
        .expect("Ed25519 keys always encode as PKCS#8")
        .as_bytes()
        .to_vec();
    let public = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
    (der, public)
}

#[must_use]
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::config_struct;

    const HOST: &str = "faces.example.test";
    const SANDBOX: &str = "sbx-7f3a";

    fn setup() -> (GuardConfig, Vec<u8>) {
        let (der, public) = generate_issuer_key();
        let config = GuardConfig::parse(Some(&config_struct(&public))).expect("config");
        (config, der)
    }

    fn claims() -> GrantClaims {
        let now = now();
        GrantClaims {
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
            parent_jti: None,
            iat: now,
            exp: now + 300,
        }
    }

    fn check(
        config: &GuardConfig,
        token: &str,
        sandbox: &str,
        host: &str,
        modality: Modality,
    ) -> Result<GrantClaims, GrantFailure> {
        let modalities = BTreeSet::from([modality]);
        verify(
            config,
            &GrantCheck {
                sandbox_id: sandbox,
                host,
                grant_values: &[token],
                modalities: &modalities,
            },
        )
    }

    #[test]
    fn valid_grant_verifies() {
        let (config, der) = setup();
        let token = sign(&claims(), &der).unwrap();
        let verified = check(&config, &token, SANDBOX, HOST, Modality::Face).unwrap();
        assert_eq!(verified.sub, "principal:3c9e");
    }

    #[test]
    fn each_mismatch_has_its_own_failure() {
        let (config, der) = setup();
        let token = sign(&claims(), &der).unwrap();
        assert_eq!(
            check(&config, &token, "sbx-other", HOST, Modality::Face),
            Err(GrantFailure::Actor)
        );
        assert_eq!(
            check(
                &config,
                &token,
                SANDBOX,
                "other.example.test",
                Modality::Face
            ),
            Err(GrantFailure::Audience)
        );
        assert_eq!(
            check(&config, &token, SANDBOX, HOST, Modality::Finger),
            Err(GrantFailure::Scope)
        );

        let mut purpose = claims();
        purpose.purpose = "marketing".into();
        let token = sign(&purpose, &der).unwrap();
        assert_eq!(
            check(&config, &token, SANDBOX, HOST, Modality::Face),
            Err(GrantFailure::Purpose)
        );

        let mut long_lived = claims();
        long_lived.exp = long_lived.iat + 86_400;
        let token = sign(&long_lived, &der).unwrap();
        assert_eq!(
            check(&config, &token, SANDBOX, HOST, Modality::Face),
            Err(GrantFailure::Lifetime)
        );

        let mut expired = claims();
        expired.exp = now() - 3600;
        let token = sign(&expired, &der).unwrap();
        assert_eq!(
            check(&config, &token, SANDBOX, HOST, Modality::Face),
            Err(GrantFailure::Expired)
        );
    }

    #[test]
    fn azp_and_spiffe_actor_forms_are_accepted_and_must_agree() {
        let (mut config, der) = setup();
        let mut azp = claims();
        azp.act = None;
        azp.azp = Some(SANDBOX.into());
        let token = sign(&azp, &der).unwrap();
        assert!(check(&config, &token, SANDBOX, HOST, Modality::Face).is_ok());

        let mut spiffe = claims();
        spiffe.act = None;
        spiffe.azp = Some(format!(
            "spiffe://openshell.local/openshell/sandbox/{SANDBOX}"
        ));
        let token = sign(&spiffe, &der).unwrap();
        assert_eq!(
            check(&config, &token, SANDBOX, HOST, Modality::Face),
            Err(GrantFailure::Actor)
        );
        config.sandbox_trust_domain = Some("openshell.local".into());
        assert!(check(&config, &token, SANDBOX, HOST, Modality::Face).is_ok());

        let mut conflicting = claims();
        conflicting.azp = Some("sbx-other".into());
        let token = sign(&conflicting, &der).unwrap();
        assert_eq!(
            check(&config, &token, SANDBOX, HOST, Modality::Face),
            Err(GrantFailure::Actor)
        );
    }

    #[test]
    fn grant_from_another_issuer_key_is_invalid() {
        let (config, _) = setup();
        let (other_der, _) = generate_issuer_key();
        let token = sign(&claims(), &other_der).unwrap();
        assert_eq!(
            check(&config, &token, SANDBOX, HOST, Modality::Face),
            Err(GrantFailure::Invalid)
        );
        assert_eq!(
            check(&config, "not.a.jwt", SANDBOX, HOST, Modality::Face),
            Err(GrantFailure::Invalid)
        );
    }

    #[test]
    fn missing_and_duplicate_grants_are_rejected() {
        let (config, der) = setup();
        let token = sign(&claims(), &der).unwrap();
        let modalities = BTreeSet::from([Modality::Face]);
        let run = |values: &[&str]| {
            verify(
                &config,
                &GrantCheck {
                    sandbox_id: SANDBOX,
                    host: HOST,
                    grant_values: values,
                    modalities: &modalities,
                },
            )
        };
        assert_eq!(run(&[]), Err(GrantFailure::Missing));
        assert_eq!(run(&[&token, &token]), Err(GrantFailure::Ambiguous));
    }
}
