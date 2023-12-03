use std::collections::HashMap;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize as _;

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct NixPublicKey {
    pub(crate) name: String,
    pub(crate) key: String,
}

impl std::fmt::Display for NixPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.name, self.key))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NixPrivateKeyPath(pub(crate) PathBuf);

impl From<&std::ffi::OsStr> for NixPrivateKeyPath {
    fn from(value: &std::ffi::OsStr) -> Self {
        Self(value.into())
    }
}

pub(crate) type NixKeypairMap = HashMap<NixPublicKey, NixPrivateKeyPath>;

#[derive(Debug, Clone, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathInfo {
    pub nar_hash: SRIHash,
    pub nar_size: u64,
    #[serde(rename = "path")]
    pub store_path: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, serde_derive::Deserialize)]
pub struct SRIHash(#[serde(deserialize_with = "deserialize_sri_hash")] pub ssri::Hash);

fn deserialize_sri_hash<'de, D>(deserializer: D) -> Result<ssri::Hash, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer)
        .and_then(|hash| hash.parse::<ssri::Hash>().map_err(serde::de::Error::custom))
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum NixHashType {
    // NOTE: ssri::Algorithm doesn't support md5, which means we can't either
    // (unless we want to reimplement SRI parsing)
    Sha1,
    Sha256,
    Sha512,
}

impl std::fmt::Display for NixHashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let algo_str = match self {
            NixHashType::Sha1 => "sha1",
            NixHashType::Sha256 => "sha256",
            NixHashType::Sha512 => "sha512",
        };

        f.write_str(algo_str)
    }
}

impl TryFrom<ssri::Algorithm> for NixHashType {
    type Error = crate::error::Report;

    fn try_from(value: ssri::Algorithm) -> std::result::Result<Self, Self::Error> {
        match value {
            ssri::Algorithm::Sha1 => Ok(NixHashType::Sha1),
            ssri::Algorithm::Sha256 => Ok(NixHashType::Sha256),
            ssri::Algorithm::Sha512 => Ok(NixHashType::Sha512),
            algo => Err(color_eyre::eyre::eyre!("Nix does not support algorithm {}", algo).into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NixBase32 {
    pub hash_type: NixHashType,
    pub digest: String,
}

impl ToString for NixBase32 {
    fn to_string(&self) -> String {
        let Self { hash_type, digest } = self;
        format!("{hash_type}:{digest}")
    }
}

impl SRIHash {
    // https://github.com/NixOS/nix/blob/78e886bc5fd9e4d85f8503799540c0b71bb270be/src/libutil/hash.cc#L85
    // ommitted: E O U T
    pub const BASE32_CHARS: &'static [u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

    // Adapted from:
    // https://github.com/NixOS/nix/blob/78e886bc5fd9e4d85f8503799540c0b71bb270be/src/libutil/hash.cc#L88-L108
    #[tracing::instrument(skip_all)]
    pub fn to_nix_base32(&self) -> Result<NixBase32> {
        let base64_digest = &self.0.digest;
        let digest_bytes = STANDARD.decode(base64_digest)?;
        let digest_len = digest_bytes.len();
        let digest_base32_len = (digest_len * 8 - 1) / 5 + 1;
        let mut base32_digest = String::with_capacity(digest_base32_len);

        for n in (0..digest_base32_len).rev() {
            let b: usize = n * 5;
            let i: usize = b / 8;
            let j: usize = b % 8;

            let x = digest_bytes[i].checked_shr(j as u32).unwrap_or(0);
            let y = if i >= digest_len - 1 {
                0
            } else {
                digest_bytes[i + 1].checked_shl(8 - j as u32).unwrap_or(0)
            };

            let c = (x | y) as usize;
            let ch = Self::BASE32_CHARS[c % Self::BASE32_CHARS.len()];
            base32_digest.push(char::from(ch));
        }

        Ok(NixBase32 {
            hash_type: self.0.algorithm.try_into()?,
            digest: base32_digest,
        })
    }
}

impl PathInfo {
    // Adapted from:
    // https://github.com/NixOS/nix/blob/ea2f74cbe178d31748d63037e238e3a4a8e02cf3/src/libstore/path-info.cc#L8-L18
    #[tracing::instrument(skip_all)]
    pub fn fingerprint(&self) -> Result<String> {
        let nar_size_string = self.nar_size.to_string();
        let references_string = self.references.join(",");
        let base32_nar_hash = self.nar_hash.to_nix_base32()?;
        let base32_nar_hash_string = base32_nar_hash.to_string();

        let fingerprint = [
            "1;",
            self.store_path.as_ref(),
            ";",
            base32_nar_hash_string.as_ref(),
            ";",
            nar_size_string.as_ref(),
            ";",
            references_string.as_ref(),
        ];

        Ok(fingerprint.into_iter().collect())
    }
}
