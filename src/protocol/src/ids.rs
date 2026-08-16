use std::fmt;
use std::str::FromStr;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

fn ser_hex<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

fn de_hex<'de, D: Deserializer<'de>, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error> {
    let s = String::deserialize(deserializer)?;
    let decoded = hex::decode(&s).map_err(D::Error::custom)?;
    decoded
        .try_into()
        .map_err(|_| D::Error::custom(format!("expected {N} bytes, got hex of other length")))
}

/// SHA-256 of a UTF-8 label. Used for deterministic test IDs.
fn sha256_16(label: &str) -> [u8; 16] {
    let hash = Sha256::digest(label.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[..16]);
    out
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Campaign identifier. Metadata does not change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CampaignId(pub [u8; 16]);

impl Serialize for CampaignId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ser_hex(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for CampaignId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(de_hex(deserializer)?))
    }
}

impl CampaignId {
    /// Deterministic ID from a label (tests and reproducible campaign dirs).
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        Self(sha256_16(label))
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for CampaignId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Worker identifier. Stable across an offline restart of the same slot
/// when the launcher reuses `WorkerId::from_slot`. A new id is a first
/// registration, not a live late join.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkerId(pub [u8; 16]);

impl Serialize for WorkerId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ser_hex(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for WorkerId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(de_hex(deserializer)?))
    }
}

impl WorkerId {
    /// Deterministic id from a label (tests and reproducible slots).
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        Self(sha256_16(label))
    }

    /// Slot `i` in a homogeneous campaign (`worker-0`, `worker-1`, …).
    #[must_use]
    pub fn from_slot(slot: u32) -> Self {
        Self::from_label(&format!("worker-{slot}"))
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for WorkerId {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 16 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes);
        Ok(Self(id))
    }
}

/// Homogeneous T2 strategy. Other capabilities wait for later tranches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyId {
    Havoc,
}

impl StrategyId {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Havoc => "havoc",
        }
    }
}

impl fmt::Display for StrategyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Logical target name, shared by every build variant of that target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetId(pub String);

impl TargetId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TargetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Content-addressed input identity. Metadata must not alter this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InputId(pub [u8; 32]);

impl Serialize for InputId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ser_hex(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for InputId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(de_hex(deserializer)?))
    }
}

impl InputId {
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(sha256_32(data))
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First two hex chars, then next two — object-store prefix.
    #[must_use]
    pub fn object_prefix(&self) -> (String, String) {
        let h = self.to_hex();
        (h[..2].to_string(), h[2..4].to_string())
    }
}

impl fmt::Display for InputId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for InputId {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(Self(id))
    }
}

/// Hash of a build's identity parts (compiler, flags, sources, kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BuildId(pub [u8; 32]);

impl Serialize for BuildId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ser_hex(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for BuildId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(de_hex(deserializer)?))
    }
}

impl BuildId {
    #[must_use]
    pub fn from_parts(parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for BuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Hash of a coverage bitmap (or of the set of hit edge indices).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoverageDigest(pub [u8; 32]);

impl Serialize for CoverageDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ser_hex(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for CoverageDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(de_hex(deserializer)?))
    }
}

impl CoverageDigest {
    #[must_use]
    pub fn from_map(map: &[u8]) -> Self {
        Self(sha256_32(map))
    }

    /// Digest of sorted hit indices. Stable across unused-tail differences
    /// when only the first `n` edges are meaningful.
    #[must_use]
    pub fn from_hit_indices(indices: &[u32]) -> Self {
        let mut hasher = Sha256::new();
        for idx in indices {
            hasher.update(idx.to_le_bytes());
        }
        Self(hasher.finalize().into())
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for CoverageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_id_is_content_addressed() {
        let a = InputId::from_bytes(b"hello");
        let b = InputId::from_bytes(b"hello");
        let c = InputId::from_bytes(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.to_hex().len(), 64);
    }

    #[test]
    fn input_id_hex_roundtrip() {
        let id = InputId::from_bytes(b"seed");
        let parsed: InputId = id.to_hex().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn campaign_id_from_label_is_stable() {
        assert_eq!(
            CampaignId::from_label("t1-demo"),
            CampaignId::from_label("t1-demo")
        );
        assert_ne!(
            CampaignId::from_label("t1-demo"),
            CampaignId::from_label("other")
        );
    }

    #[test]
    fn worker_id_slot_is_stable_and_distinct() {
        assert_eq!(WorkerId::from_slot(0), WorkerId::from_slot(0));
        assert_ne!(WorkerId::from_slot(0), WorkerId::from_slot(1));
        let id = WorkerId::from_slot(2);
        let parsed: WorkerId = id.to_hex().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn strategy_id_json_is_havoc() {
        let json = serde_json::to_string(&StrategyId::Havoc).unwrap();
        assert_eq!(json, "\"havoc\"");
        assert_eq!(
            serde_json::from_str::<StrategyId>(&json).unwrap(),
            StrategyId::Havoc
        );
    }

    #[test]
    fn object_prefix_is_two_plus_two() {
        let id = InputId::from_bytes(b"x");
        let (a, b) = id.object_prefix();
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
        assert!(id.to_hex().starts_with(&format!("{a}{b}")));
    }

    #[test]
    fn digest_json_is_hex_string() {
        let d = CoverageDigest::from_map(&[1, 0, 2]);
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            json.starts_with('"'),
            "digest must serialize as a hex string, got {json}"
        );
        assert_eq!(json.len(), 66);
        assert_eq!(serde_json::from_str::<CoverageDigest>(&json).unwrap(), d);
    }

    #[test]
    fn coverage_digest_distinguishes_maps() {
        let mut m1 = [0u8; 8];
        let mut m2 = [0u8; 8];
        m1[1] = 1;
        m2[2] = 1;
        assert_ne!(CoverageDigest::from_map(&m1), CoverageDigest::from_map(&m2));
        assert_eq!(
            CoverageDigest::from_hit_indices(&[1, 3]),
            CoverageDigest::from_hit_indices(&[1, 3])
        );
    }
}
