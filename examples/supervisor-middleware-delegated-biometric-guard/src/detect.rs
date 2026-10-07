// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Best-effort detection of biometric artifacts in an outbound request body.
//!
//! Detection is deliberately narrow and explainable. It recognizes three
//! signals and nothing else:
//!
//! 1. ISO/IEC 19794 biometric data interchange records, identified by their
//!    four-byte format identifier (`FMR\0`, `FIR\0`, `FAC\0`, `IIR\0`), either as
//!    the raw body or as a base64 string inside a JSON body.
//! 2. JSON fields whose names are unambiguous biometric terms (for example
//!    `face_embedding`, `iris_code`, `voiceprint`, `minutiae`). A numeric
//!    vector or an ISO record under such a key raises confidence to `high`.
//! 3. Inline images (base64 JPEG, PNG, WebP or `data:image/` URIs), only for
//!    destinations the operator lists in `image_hosts`, such as a face
//!    verification vendor. Without a face detector, an image is only treated as
//!    biometric where the operator has said it is.
//!
//! Bare `fingerprint` is intentionally not a biometric key: in HTTP APIs it
//! usually means a TLS, SSH, or device fingerprint.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use serde_json::Value;

const MAX_JSON_DEPTH: usize = 64;
const MIN_EMBEDDING_LEN: usize = 32;
/// Characters of base64 needed to recover the first six decoded bytes.
const BASE64_PREFIX_CHARS: usize = 8;
const MIN_BASE64_CANDIDATE_CHARS: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Modality {
    Face,
    Finger,
    Iris,
    Voice,
    Palm,
}

impl Modality {
    pub const ALL: [Modality; 5] = [
        Modality::Face,
        Modality::Finger,
        Modality::Iris,
        Modality::Voice,
        Modality::Palm,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Modality::Face => "face",
            Modality::Finger => "finger",
            Modality::Iris => "iris",
            Modality::Voice => "voice",
            Modality::Palm => "palm",
        }
    }

    /// OAuth-style scope a delegation grant must carry to cover this modality.
    #[must_use]
    pub fn scope(self) -> String {
        format!("biometric:{}", self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Medium,
    High,
}

impl Confidence {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    pub count: u32,
    pub confidence: Confidence,
}

/// Modalities found in a body, with a match count and the strongest
/// confidence observed for each. Never carries matched values.
pub type Detections = BTreeMap<Modality, Hit>;

fn record(detections: &mut Detections, modality: Modality, confidence: Confidence) {
    detections
        .entry(modality)
        .and_modify(|hit| {
            hit.count = hit.count.saturating_add(1);
            hit.confidence = hit.confidence.max(confidence);
        })
        .or_insert(Hit {
            count: 1,
            confidence,
        });
}

/// Inspect a request body. `treat_images_as_face` is true only when the
/// destination is one the operator listed in `image_hosts`.
#[must_use]
pub fn detect(body: &[u8], treat_images_as_face: bool) -> Detections {
    let mut detections = Detections::new();
    if let Some(modality) = iso_19794_modality(body) {
        record(&mut detections, modality, Confidence::High);
        return detections;
    }
    if treat_images_as_face && is_image(body) {
        record(&mut detections, Modality::Face, Confidence::Medium);
        return detections;
    }
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        walk(&value, 0, treat_images_as_face, &mut detections);
    }
    detections
}

fn walk(value: &Value, depth: usize, images: bool, detections: &mut Detections) {
    if depth > MAX_JSON_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if let Some(modality) = key_modality(key) {
                    let confidence = if is_numeric_vector(child) || encoded_record(child).is_some()
                    {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };
                    record(detections, modality, confidence);
                    // The key already accounts for this value; do not count
                    // an ISO record beneath it twice.
                    if encoded_record(child).is_some() {
                        continue;
                    }
                }
                walk(child, depth + 1, images, detections);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, depth + 1, images, detections);
            }
        }
        Value::String(text) => {
            if let Some(modality) = encoded_record(value) {
                record(detections, modality, Confidence::High);
            } else if images && string_is_image(text) {
                record(detections, Modality::Face, Confidence::Medium);
            }
        }
        _ => {}
    }
}

/// Map a JSON key to a modality when the key is an unambiguous biometric term.
#[must_use]
pub fn key_modality(key: &str) -> Option<Modality> {
    let mut normalized: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if normalized.ends_with('s') && normalized.len() > 4 {
        normalized.pop();
    }
    let modality = match normalized.as_str() {
        "faceembedding" | "faceprint" | "facetemplate" | "faceencoding" | "facevector"
        | "facedescriptor" | "facefeature" | "facialembedding" | "facialtemplate"
        | "facialfeature" => Modality::Face,
        "fingerprinttemplate"
        | "fingerprintminutiae"
        | "fingerprintminutia"
        | "minutiae"
        | "minutia"
        | "fingertemplate"
        | "fingerprintimage" => Modality::Finger,
        "iriscode" | "iristemplate" | "irisembedding" | "irisimage" => Modality::Iris,
        "voiceprint" | "speakerembedding" | "voiceembedding" | "voicetemplate"
        | "speakertemplate" => Modality::Voice,
        "palmprint" | "palmtemplate" | "palmveintemplate" => Modality::Palm,
        _ => return None,
    };
    Some(modality)
}

fn is_numeric_vector(value: &Value) -> bool {
    match value {
        Value::Array(items) => {
            items.len() >= MIN_EMBEDDING_LEN && items.iter().all(Value::is_number)
        }
        _ => false,
    }
}

/// ISO/IEC 19794 format identifiers (four bytes at the start of a record).
fn iso_19794_modality(bytes: &[u8]) -> Option<Modality> {
    match bytes.get(..4)? {
        b"FMR\0" | b"FIR\0" => Some(Modality::Finger),
        b"FAC\0" => Some(Modality::Face),
        b"IIR\0" => Some(Modality::Iris),
        _ => None,
    }
}

fn is_image(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        || bytes.starts_with(b"\x89PNG")
        || (bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
}

fn encoded_record(value: &Value) -> Option<Modality> {
    let Value::String(text) = value else {
        return None;
    };
    decode_prefix(strip_data_uri(text)).and_then(|prefix| iso_19794_modality(&prefix))
}

fn string_is_image(text: &str) -> bool {
    if text.starts_with("data:image/") {
        return true;
    }
    decode_prefix(text).is_some_and(|prefix| is_image(&prefix))
}

fn strip_data_uri(text: &str) -> &str {
    if text.starts_with("data:")
        && let Some((_, payload)) = text.split_once(";base64,")
    {
        return payload;
    }
    text
}

/// Decode only the first bytes of a long base64 string, so large payloads are
/// never fully decoded just to check a signature.
fn decode_prefix(text: &str) -> Option<Vec<u8>> {
    if text.len() < MIN_BASE64_CANDIDATE_CHARS {
        return None;
    }
    let prefix = text.get(..BASE64_PREFIX_CHARS)?;
    STANDARD_NO_PAD
        .decode(prefix)
        .or_else(|_| URL_SAFE_NO_PAD.decode(prefix))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;

    fn iso_record(identifier: &[u8; 4]) -> String {
        let mut record = identifier.to_vec();
        record.extend_from_slice(b" 20\0 fake record payload bytes for tests");
        STANDARD.encode(record)
    }

    #[test]
    fn clean_json_has_no_detections() {
        let body = json!({"prompt": "summarize this", "embedding": vec![0.1; 1536]});
        assert!(detect(body.to_string().as_bytes(), false).is_empty());
    }

    #[test]
    fn device_and_tls_fingerprints_are_not_biometric() {
        let body = json!({"fingerprint": "SHA256:abc", "device_fingerprint": "f00d"});
        assert!(detect(body.to_string().as_bytes(), false).is_empty());
    }

    #[test]
    fn named_face_embedding_is_high_confidence() {
        let body = json!({"user": {"face_embedding": vec![0.01; 512]}});
        let found = detect(body.to_string().as_bytes(), false);
        assert_eq!(
            found.get(&Modality::Face),
            Some(&Hit {
                count: 1,
                confidence: Confidence::High
            })
        );
    }

    #[test]
    fn named_key_without_vector_is_medium_confidence() {
        let body = json!({"voiceprint": "opaque-vendor-handle"});
        let found = detect(body.to_string().as_bytes(), false);
        assert_eq!(found[&Modality::Voice].confidence, Confidence::Medium);
    }

    #[test]
    fn iso_records_are_recognized_in_json_and_raw() {
        let body = json!({"attachments": [iso_record(b"FMR\0"), iso_record(b"IIR\0")]});
        let found = detect(body.to_string().as_bytes(), false);
        assert_eq!(found[&Modality::Finger].confidence, Confidence::High);
        assert_eq!(found[&Modality::Iris].confidence, Confidence::High);

        let raw = b"FAC\0 010\0 raw face record";
        assert!(detect(raw, false).contains_key(&Modality::Face));
    }

    #[test]
    fn iso_record_under_biometric_key_counts_once() {
        let body = json!({"iris_template": iso_record(b"IIR\0")});
        let found = detect(body.to_string().as_bytes(), false);
        assert_eq!(found[&Modality::Iris].count, 1);
    }

    #[test]
    fn images_count_only_for_listed_hosts() {
        let jpeg = STANDARD.encode([
            0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0,
        ]);
        let body = json!({"image": jpeg});
        assert!(detect(body.to_string().as_bytes(), false).is_empty());
        assert!(detect(body.to_string().as_bytes(), true).contains_key(&Modality::Face));
        let uri = json!({"selfie": "data:image/png;base64,iVBORw0KGgo"});
        assert!(detect(uri.to_string().as_bytes(), true).contains_key(&Modality::Face));
    }

    #[test]
    fn key_normalization_handles_case_separators_and_plurals() {
        assert_eq!(key_modality("FaceEmbeddings"), Some(Modality::Face));
        assert_eq!(key_modality("speaker-embedding"), Some(Modality::Voice));
        assert_eq!(key_modality("iris_code"), Some(Modality::Iris));
        assert_eq!(key_modality("face"), None);
    }
}
