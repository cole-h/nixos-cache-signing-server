use crate::nix::{PathInfo, SRIHash};

const SECRET_KEY_FILE_CONTENTS: &str = include_str!("../secret-key");
const PUBLIC_KEY_FILE_CONTENTS: &str = include_str!("../public-key");

/*
[
  {
    "deriver": "/nix/store/vz9naq2p06k5sagqz5mxcbmff0a4d3hb-hello-2.12.1.drv",
    "narHash": "sha256-sXrPtjqhSoc2u0YfM1HVZThknkSYuRuHdtKCB6wkDFo=",
    "narSize": 226552,
    "path": "/nix/store/mdi7lvrn2mx7rfzv3fdq3v5yw8swiks6-hello-2.12.1",
    "references": [
      "/nix/store/aw2fw9ag10wr9pf0qk4nk5sxi0q0bn56-glibc-2.37-8",
      "/nix/store/mdi7lvrn2mx7rfzv3fdq3v5yw8swiks6-hello-2.12.1"
    ],
    "registrationTime": 1696097829,
    "signatures": [
      "cache.nixos.org-1:7guDbfaF2Q29HY0c5axhtuacfxN6uxuEqeUfncDiSvMSAWvfHVMppB89ILqV8FE58pEQ04tSbMnRhR3FGPV0AA=="
    ],
    "valid": true
  }
]
*/
fn test_path_info() -> PathInfo {
    PathInfo {
        nar_hash: SRIHash(
            "sha256-sXrPtjqhSoc2u0YfM1HVZThknkSYuRuHdtKCB6wkDFo="
                .parse()
                .unwrap(),
        ),
        nar_size: 226552,
        store_path: String::from("/nix/store/mdi7lvrn2mx7rfzv3fdq3v5yw8swiks6-hello-2.12.1"),
        references: vec![
            String::from("/nix/store/aw2fw9ag10wr9pf0qk4nk5sxi0q0bn56-glibc-2.37-8"),
            String::from("/nix/store/mdi7lvrn2mx7rfzv3fdq3v5yw8swiks6-hello-2.12.1"),
        ],
    }
}

#[test]
fn test_fingerprint_generation() {
    let path_info = test_path_info();
    let fingerprint = path_info.fingerprint().unwrap();

    assert_eq!(
        fingerprint,
        "1;/nix/store/mdi7lvrn2mx7rfzv3fdq3v5yw8swiks6-hello-2.12.1;sha256:0nhc4jn0g0njfs3ipfcq8jg68f35sm8k67s6pcv8fjm17avcyymi;226552;/nix/store/aw2fw9ag10wr9pf0qk4nk5sxi0q0bn56-glibc-2.37-8,/nix/store/mdi7lvrn2mx7rfzv3fdq3v5yw8swiks6-hello-2.12.1"
    );
}

#[tokio::test]
async fn test_fingerprint_signing() {
    let path_info = test_path_info();
    let fingerprint = path_info.fingerprint().unwrap();
    let fingerprint = bytes::Bytes::from(fingerprint);

    let expected_signature = "test-1:TS12zri2hld72xAwjPUyL0MGqcmbWtHuAFFoRCXu6PwFVd0Awqe4+wgENU7XbWm/itTWumccNX+c7DVFZqKVCA==";
    let signature = super::sign_fingerprint_with_secret_key(&fingerprint, SECRET_KEY_FILE_CONTENTS)
        .await
        .expect("should have gotten a fingerprint");

    assert_eq!(signature, expected_signature);
}

#[test]
fn test_pubkey_generation() {
    let public_key = super::secret_key_to_public_key(SECRET_KEY_FILE_CONTENTS).unwrap();
    assert_eq!(public_key, PUBLIC_KEY_FILE_CONTENTS);
}
