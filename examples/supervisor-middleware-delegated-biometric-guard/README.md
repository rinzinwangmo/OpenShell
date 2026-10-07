<!--
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor Middleware: Delegated Biometric Guard

> [!WARNING]
> Supervisor middleware is a research preview, and this is an example. Detection is best-effort and deliberately narrow. Do not rely on it alone to control biometric data.

This operator-run middleware lets biometric data leave a sandbox only when the request carries a signed delegation grant that names:

- the **human principal** the agent is acting for,
- the **sandbox** doing the acting,
- the **destination** the data may go to,
- the **biometric modalities** covered (`biometric:face`, `biometric:voice`, and so on), and
- the **purpose**, which policy must allow.

Biometric data identifies a person durably, so this example treats biometric egress as its own data class: it is allowed only under an explicit, narrow, short-lived delegation, and never on a sandbox's general network permissions alone.

## What it does on each request

The guard runs at `HTTP_REQUEST/PRE_CREDENTIALS`, after network policy admits the request and before OpenShell injects credentials.

1. **Detect.** Look for biometric data in the body (see [Detection](#detection)). If there is none, allow the request unchanged.
2. **Verify.** If there is biometric data, verify the grant in the `x-agent-delegation` header: EdDSA signature from the configured issuer, not expired, audience equals the admitted destination host, actor equals the sandbox id from OpenShell's request context, a scope for every detected modality, and a purpose on the policy's allow-list.
3. **Decide.** In `enforce` mode, deny with a stable reason code when any check fails. In `audit` mode, allow and report what would have been denied.
4. **Strip.** Remove the grant header from every request that carries one, so the grant is never sent to the destination.

| Reason code | Meaning |
| --- | --- |
| `biometric_delegation_missing` | Biometric data with no grant |
| `biometric_delegation_ambiguous` | More than one grant header |
| `biometric_delegation_invalid` | Bad signature, wrong issuer, or malformed grant |
| `biometric_delegation_expired` | Grant expired or not yet valid |
| `biometric_delegation_audience` | Grant is for a different destination host |
| `biometric_delegation_actor` | Grant was issued to a different sandbox |
| `biometric_delegation_scope` | Grant does not cover a detected modality |
| `biometric_delegation_purpose` | Grant names a purpose policy does not allow |
| `biometric_delegation_lifetime` | Grant is valid for longer than `max_grant_lifetime_seconds` |

## Try it

The demo starts the guard as a gRPC service and drives it through `openshell-supervisor-middleware`, the chain runner the sandbox supervisor uses. That covers service registration and `Describe`, `ValidateConfig`, evaluation, and OpenShell's validation of the header removal. No container runtime is needed.

```shell
cd examples/supervisor-middleware-delegated-biometric-guard
cargo run --bin demo
cargo test
```

The demo runs eight requests to a face-verification vendor: an ordinary request, a face embedding with and without a grant, the same grant replayed from another sandbox, sent to another host, used for a fingerprint template it does not cover, issued for an unapproved purpose, and expired. Only the ordinary request and the correctly delegated one are allowed.

For each request it also prints what the guard attributed (principal, purpose, delegation id) next to what reaches OpenShell's outputs. See [Attribution](#attribution-what-this-example-cannot-do-yet).

The full sandbox path (gateway, supervisor image, live sandbox) has not been run for this example. The content-guard example's `smoke.sh` shows that setup.

## Run it with a gateway

Start the service:

```shell
cargo run --bin delegated-biometric-guard -- --bind 0.0.0.0:50061
```

Register it in the gateway TOML:

```toml
[[openshell.supervisor.middleware]]
name = "delegated-biometric-guard"
grpc_endpoint = "http://host.openshell.internal:50061"
allow_insecure_transport = true
max_payload_bytes = 1048576
timeout = "500ms"
```

Create an issuer key, put the printed public key in `policy.yaml`, and create the sandbox:

```shell
cargo run --bin mint-grant -- keygen
openshell sandbox create --policy examples/supervisor-middleware-delegated-biometric-guard/policy.yaml
```

Mint a grant for that sandbox and send a request from inside it:

```shell
GRANT=$(cargo run -q --bin mint-grant -- mint \
  --issuer https://idp.example.test --principal principal:3c9e81 \
  --sandbox <sandbox-id> --audience httpbin.org \
  --modalities face --purpose identity_verification)

curl -sS https://httpbin.org/anything \
  --header "x-agent-delegation: $GRANT" \
  --header 'content-type: application/json' \
  --data '{"face_embedding":[0.01,0.02, ...]}'
```

`mint-grant` stands in for an authorization server. In a real deployment, grants would come from the organization's authorization server or token-exchange service, and the agent would never hold the issuer key.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `issuer` | Yes | Expected `iss` of every grant. |
| `issuer_public_key` | Yes | Issuer's Ed25519 public key, base64url (the JWK `x` value). |
| `allowed_purposes` | Yes | Purposes a grant may name. |
| `mode` | No | `enforce` (default) or `audit`. |
| `grant_header` | No | Header carrying the grant. Defaults to `x-agent-delegation`. Headers that OpenShell withholds from middleware, such as `authorization`, are rejected. |
| `image_hosts` | No | Destinations where any inline image counts as face data, such as a face-verification vendor. |
| `sandbox_trust_domain` | No | Also accept `spiffe://<domain>/openshell/sandbox/<id>` as the actor. |
| `clock_skew_seconds` | No | Allowed clock skew, 0 to 300. Defaults to 30. |
| `max_grant_lifetime_seconds` | No | Longest validity window (`exp` minus `iat`) a grant may carry, 1 to 3600. Defaults to 600. |

## Grant format

A grant is a compact JWS (a JWT signed with EdDSA). Claim names follow existing standards so an ordinary authorization server can issue one.

| Claim | Meaning |
| --- | --- |
| `iss` | Issuing authority |
| `sub` | Human principal, ideally a pseudonymous id |
| `act.sub` or `azp` | Acting sandbox: the sandbox id, or its SPIFFE id when `sandbox_trust_domain` is set. `act` is the RFC 8693 actor claim; `azp` is the form proposed for OpenShell's user-subject token grants in [#1987](https://github.com/NVIDIA/OpenShell/issues/1987). If both appear, they must agree. |
| `aud` | Destination host |
| `scope` | Space-separated `biometric:<modality>` values |
| `purpose` | Declared purpose |
| `jti` | Delegation id |
| `parent_jti` | Optional parent delegation, for re-delegation |
| `iat`, `exp` | Issue and expiry times |

`jti`, `iss`, `parent_jti`, and `iat` correspond to the `uid`, `issuer_uid`, `parent_uid`, and `created_time` fields of the `delegation` object in the OCSF schema's current development version.

## Detection

Detection covers three signals and nothing else:

- **ISO/IEC 19794 records**, identified by their format identifier (`FMR`, `FIR`, `FAC`, `IIR`), either as the raw body or base64 inside JSON.
- **JSON keys that are unambiguous biometric terms**, such as `face_embedding`, `iris_code`, `voiceprint`, `speaker_embedding`, and `minutiae`. Confidence is `high` when the value is a numeric vector or an ISO record, and `medium` otherwise. A bare `fingerprint` key is ignored because in HTTP APIs it usually means a TLS, SSH, or device fingerprint.
- **Inline images** (JPEG, PNG, WebP, `data:image/` URIs), only for hosts listed in `image_hosts`. There is no face detector here, so an image counts as biometric only where the operator has said it does.

It does not decode compressed or multipart bodies, recognize vendor-specific binary templates, or catch data that has been renamed or encoded to avoid detection.

## Attribution: what this example cannot do yet

The guard knows who authorized each biometric transfer, but that attribution does not reach OpenShell's audit output. This is deliberate platform behavior, not a bug in the example.

OpenShell treats text from operator-run middleware as untrusted. It clears the metadata such a service returns and replaces its finding types and labels with platform-owned values (`normalize_untrusted_diagnostics` in `crates/openshell-supervisor-middleware`). OpenShell's OCSF `Actor` object currently records the originating process only.

In practice:

- **Enforcement works today.** Denials and their reason codes reach the agent, and the audit trail shows that the guard produced findings.
- **Attribution does not.** "Principal X authorized this face template to go to vendor Y for identity verification under delegation Z" stays inside the guard.

The test `attribution_from_operator_run_middleware_does_not_reach_openshell_outputs` documents this, so a platform change that affects it will show up as a failing test.

Closing the gap needs a platform-level change: OpenShell, not an operator-run service, would verify the delegation and record it. That would build on [#1987](https://github.com/NVIDIA/OpenShell/issues/1987) (user-subject token grants) and [#3837](https://github.com/NVIDIA/OpenShell/issues/3837) (recording the approving principal).

## Limits of the header-carried grant

- **The grant is a bearer token within its bounds.** Any process in the sandbox that can read it can use it until it expires, but only from that sandbox, to that host, for those modalities and that purpose. The guard rejects grants whose lifetime exceeds `max_grant_lifetime_seconds`.
- **There is no replay cache.** A grant can be used more than once within its lifetime.
- **Uninspected traffic is outside the guard's reach.** OpenShell does not inspect HTTP/2, `tls: skip` endpoints, or opaque TCP, so the guard cannot see that traffic. Network policy should not route biometric destinations through those paths.
