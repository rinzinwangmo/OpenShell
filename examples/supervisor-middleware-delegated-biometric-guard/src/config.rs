// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy configuration for one `network_middlewares` entry.

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::DecodingKey;
use prost_types::Struct;
use prost_types::value::Kind;

pub const DEFAULT_GRANT_HEADER: &str = "x-agent-delegation";
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 30;
const MAX_CLOCK_SKEW_SECONDS: u64 = 300;
const DEFAULT_MAX_GRANT_LIFETIME_SECONDS: u64 = 600;
const MAX_GRANT_LIFETIME_CEILING_SECONDS: u64 = 3600;
const FIELDS: &[&str] = &[
    "mode",
    "grant_header",
    "issuer",
    "issuer_public_key",
    "allowed_purposes",
    "image_hosts",
    "clock_skew_seconds",
    "max_grant_lifetime_seconds",
    "sandbox_trust_domain",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Deny biometric egress that is not covered by a valid grant.
    Enforce,
    /// Allow it, but report what enforcement would have denied.
    Audit,
}

impl Mode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::Audit => "audit",
        }
    }
}

#[derive(Clone)]
pub struct GuardConfig {
    pub mode: Mode,
    /// Lowercased request header that carries the delegation grant.
    pub grant_header: String,
    /// Expected `iss` of every grant.
    pub issuer: String,
    /// Ed25519 verification key of the issuer.
    pub decoding_key: DecodingKey,
    /// Purposes a grant may name. A grant for any other purpose is rejected.
    pub allowed_purposes: BTreeSet<String>,
    /// Destinations where any inline image counts as face biometric data.
    pub image_hosts: BTreeSet<String>,
    pub clock_skew_seconds: u64,
    /// Longest validity window (`exp` minus `iat`) a grant may carry.
    pub max_grant_lifetime_seconds: u64,
    /// SPIFFE trust domain. When set, a grant may name its actor as
    /// `spiffe://<domain>/openshell/sandbox/<sandbox-id>`.
    pub sandbox_trust_domain: Option<String>,
}

impl std::fmt::Debug for GuardConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardConfig")
            .field("mode", &self.mode)
            .field("grant_header", &self.grant_header)
            .field("issuer", &self.issuer)
            .field("allowed_purposes", &self.allowed_purposes)
            .field("image_hosts", &self.image_hosts)
            .field("clock_skew_seconds", &self.clock_skew_seconds)
            .field(
                "max_grant_lifetime_seconds",
                &self.max_grant_lifetime_seconds,
            )
            .field("sandbox_trust_domain", &self.sandbox_trust_domain)
            .finish_non_exhaustive()
    }
}

impl GuardConfig {
    /// Parse and validate the service-specific `config` block from policy.
    pub fn parse(config: Option<&Struct>) -> Result<Self, String> {
        let config = config.ok_or_else(|| "config is required".to_string())?;
        if let Some(field) = config
            .fields
            .keys()
            .find(|field| !FIELDS.contains(&field.as_str()))
        {
            return Err(format!("unsupported config field '{field}'"));
        }

        let mode = match optional_string(config, "mode")?.unwrap_or("enforce") {
            "enforce" => Mode::Enforce,
            "audit" => Mode::Audit,
            _ => return Err("config.mode must be 'enforce' or 'audit'".into()),
        };

        let grant_header = optional_string(config, "grant_header")?
            .unwrap_or(DEFAULT_GRANT_HEADER)
            .to_ascii_lowercase();
        validate_grant_header(&grant_header)?;

        let issuer = required_string(config, "issuer")?.to_string();

        let key = required_string(config, "issuer_public_key")?;
        let raw = URL_SAFE_NO_PAD
            .decode(key.trim_end_matches('='))
            .map_err(|_| {
                "config.issuer_public_key must be base64url (JWK 'x' value)".to_string()
            })?;
        if raw.len() != 32 {
            return Err("config.issuer_public_key must be a 32-byte Ed25519 public key".into());
        }
        let decoding_key = DecodingKey::from_ed_components(&URL_SAFE_NO_PAD.encode(&raw))
            .map_err(|_| "config.issuer_public_key is not a valid Ed25519 key".to_string())?;

        let allowed_purposes = string_set(config, "allowed_purposes")?
            .ok_or_else(|| "config.allowed_purposes is required".to_string())?;
        if allowed_purposes.is_empty() {
            return Err("config.allowed_purposes must name at least one purpose".into());
        }

        let image_hosts = string_set(config, "image_hosts")?
            .unwrap_or_default()
            .into_iter()
            .map(|host| host.to_ascii_lowercase())
            .collect();

        let clock_skew_seconds = whole_number(
            config,
            "clock_skew_seconds",
            DEFAULT_CLOCK_SKEW_SECONDS,
            0,
            MAX_CLOCK_SKEW_SECONDS,
        )?;

        let max_grant_lifetime_seconds = whole_number(
            config,
            "max_grant_lifetime_seconds",
            DEFAULT_MAX_GRANT_LIFETIME_SECONDS,
            1,
            MAX_GRANT_LIFETIME_CEILING_SECONDS,
        )?;

        let sandbox_trust_domain = optional_string(config, "sandbox_trust_domain")?
            .map(|domain| {
                if domain.is_empty() || domain.contains('/') || domain.contains(':') {
                    Err("config.sandbox_trust_domain must be a bare trust domain such as 'example.org'".to_string())
                } else {
                    Ok(domain.to_ascii_lowercase())
                }
            })
            .transpose()?;

        Ok(Self {
            mode,
            grant_header,
            issuer,
            decoding_key,
            allowed_purposes,
            image_hosts,
            clock_skew_seconds,
            max_grant_lifetime_seconds,
            sandbox_trust_domain,
        })
    }
}

/// OpenShell never shows credential-bearing headers to middleware, so a grant
/// carried in one of them would be invisible and every request would look
/// undelegated. Reject those names up front instead of failing silently.
fn validate_grant_header(name: &str) -> Result<(), String> {
    let valid_chars = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !valid_chars {
        return Err("config.grant_header must contain only letters, digits, and '-'".into());
    }
    let hidden = matches!(
        name,
        "authorization" | "proxy-authorization" | "cookie" | "host"
    ) || name.starts_with("x-openshell-credential")
        || name.starts_with("x-amz-");
    if hidden {
        return Err(format!(
            "config.grant_header '{name}' is withheld from middleware by OpenShell; choose a custom header"
        ));
    }
    Ok(())
}

fn whole_number(
    config: &Struct,
    name: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, String> {
    match config.fields.get(name) {
        None => Ok(default),
        Some(value) => match value.kind.as_ref() {
            Some(Kind::NumberValue(number))
                if number.fract() == 0.0 && *number >= min as f64 && *number <= max as f64 =>
            {
                Ok(*number as u64)
            }
            _ => Err(format!(
                "config.{name} must be a whole number from {min} to {max}"
            )),
        },
    }
}

fn optional_string<'a>(config: &'a Struct, name: &str) -> Result<Option<&'a str>, String> {
    match config.fields.get(name).map(|value| value.kind.as_ref()) {
        None => Ok(None),
        Some(Some(Kind::StringValue(value))) => Ok(Some(value.as_str())),
        Some(_) => Err(format!("config.{name} must be a string")),
    }
}

fn required_string<'a>(config: &'a Struct, name: &str) -> Result<&'a str, String> {
    match optional_string(config, name)? {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(format!("config.{name} is required")),
    }
}

fn string_set(config: &Struct, name: &str) -> Result<Option<BTreeSet<String>>, String> {
    let Some(value) = config.fields.get(name) else {
        return Ok(None);
    };
    let Some(Kind::ListValue(list)) = value.kind.as_ref() else {
        return Err(format!("config.{name} must be a list of strings"));
    };
    let mut set = BTreeSet::new();
    for item in &list.values {
        match item.kind.as_ref() {
            Some(Kind::StringValue(text)) if !text.is_empty() => {
                set.insert(text.clone());
            }
            _ => return Err(format!("config.{name} must contain only non-empty strings")),
        }
    }
    Ok(Some(set))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use prost_types::{ListValue, Value};

    pub(crate) fn string(value: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(value.into())),
        }
    }

    pub(crate) fn list(values: &[&str]) -> Value {
        Value {
            kind: Some(Kind::ListValue(ListValue {
                values: values.iter().map(|v| string(v)).collect(),
            })),
        }
    }

    pub(crate) fn config_struct(public_key: &str) -> Struct {
        Struct {
            fields: [
                ("issuer".to_string(), string("https://idp.example.test")),
                ("issuer_public_key".to_string(), string(public_key)),
                (
                    "allowed_purposes".to_string(),
                    list(&["identity_verification"]),
                ),
                ("image_hosts".to_string(), list(&["Faces.Example.Test"])),
            ]
            .into_iter()
            .collect(),
        }
    }

    const KEY: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    #[test]
    fn parses_defaults() {
        let config = GuardConfig::parse(Some(&config_struct(KEY))).expect("valid config");
        assert_eq!(config.mode, Mode::Enforce);
        assert_eq!(config.grant_header, DEFAULT_GRANT_HEADER);
        assert!(config.image_hosts.contains("faces.example.test"));
        assert_eq!(config.clock_skew_seconds, 30);
        assert_eq!(config.max_grant_lifetime_seconds, 600);
    }

    #[test]
    fn bounds_the_grant_lifetime_setting() {
        let number = |n: f64| Value {
            kind: Some(Kind::NumberValue(n)),
        };
        let mut config = config_struct(KEY);
        config
            .fields
            .insert("max_grant_lifetime_seconds".into(), number(120.0));
        let parsed = GuardConfig::parse(Some(&config)).expect("valid config");
        assert_eq!(parsed.max_grant_lifetime_seconds, 120);

        for bad in [0.0, 3601.0, 1.5] {
            config
                .fields
                .insert("max_grant_lifetime_seconds".into(), number(bad));
            assert!(GuardConfig::parse(Some(&config)).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_unknown_fields_and_hidden_headers() {
        let mut config = config_struct(KEY);
        config.fields.insert("extra".into(), string("x"));
        assert!(GuardConfig::parse(Some(&config)).is_err());

        let mut config = config_struct(KEY);
        config
            .fields
            .insert("grant_header".into(), string("Authorization"));
        let error = GuardConfig::parse(Some(&config)).unwrap_err();
        assert!(error.contains("withheld"), "{error}");
    }

    #[test]
    fn rejects_bad_keys_and_empty_purposes() {
        assert!(GuardConfig::parse(Some(&config_struct("not-a-key"))).is_err());
        let mut config = config_struct(KEY);
        config.fields.insert("allowed_purposes".into(), list(&[]));
        assert!(GuardConfig::parse(Some(&config)).is_err());
    }
}
