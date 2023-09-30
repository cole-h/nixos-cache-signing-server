mod cli;
mod error;
mod trace_layer;

use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::os::unix::prelude::OsStrExt;
use std::path::PathBuf;
use std::process::Stdio;

use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose;
use base64::Engine as _;
use clap::Parser;
use dryoc::constants::CRYPTO_SIGN_ED25519_SECRETKEYBYTES;
use ed25519_dalek::Digest;
use ed25519_dalek::{Sha512, SigningKey, SECRET_KEY_LENGTH};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tower_http::trace::TraceLayer;

use crate::error::Result;

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
#[derive(Debug, Clone, serde_derive::Deserialize)]
struct NixPathInfo {
    signatures: HashSet<String>,
}

#[tokio::main]
// FIXME: add axum state that includes the public and private keys?
// (at the very least, keep the public key in memory, since that's not very important)
async fn main() -> Result<()> {
    color_eyre::config::HookBuilder::default()
        .theme(if !std::io::stderr().is_terminal() {
            // Don't attempt color
            color_eyre::config::Theme::new()
        } else {
            color_eyre::config::Theme::dark()
        })
        .install()?;

    let cli = cli::Cli::parse();
    cli.instrumentation.setup()?;

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(trace_layer::trace_layer_make_span_with)
        .on_request(trace_layer::trace_layer_on_request)
        .on_response(trace_layer::trace_layer_on_response);

    let app = Router::new()
        .route("/sign", post(sign))
        .route("/sign-nar", post(sign_realisation))
        .route(
            "/publickey",
            get(|| async { "test-1:rF0EjRCykUUAT5VLmYw9JiVQKb9otHAVhobICIDOefY=" }),
        )
        // TODO: maybe make this a nix cache "wrapper" -- maybe even use https://github.com/lheckemann/nixstore-rs :eyes:
        // .route(
        //     "/store/nix-cache-info",
        //     get(|| async { "StoreDir: /nix/store" }),
        // )
        .fallback(not_found)
        .layer(trace_layer);

    tracing::info!("listening on {}", &cli.bind);
    axum::Server::bind(&cli.bind)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

async fn not_found() -> impl IntoResponse {
    (hyper::StatusCode::NOT_FOUND, "Not Found").into_response()
}

// TODO: what's the workflow? `nix copy --to this_box` and then send the storepath to us?
// or maybe upload the nar itself and somehow register that to the store?
async fn sign(
    // TODO
    store_path: String,
) -> Result<impl IntoResponse> {
    // TODO: content type shenanigans: https://github.com/tokio-rs/axum/blob/main/examples/parse-body-based-on-content-type/src/main.rs
    let store_path = PathBuf::from(store_path);

    if !store_path.exists() {
        return Err(color_eyre::eyre::eyre!("doesn't exist").into());
    }

    let secret_key_path = "./secret-key"; // FIXME: PathBuf

    tracing::debug!(
        "extracting original signatures from store path '{}'",
        store_path.display()
    );
    let nix_path_info_output = Command::new("nix")
        .args(["--extra-experimental-features", "nix-command"])
        .arg("path-info")
        .arg("--json")
        .arg(&store_path)
        .output()
        .await?;

    let nix_path_infos: Vec<NixPathInfo> = serde_json::from_slice(&nix_path_info_output.stdout)?;
    let nix_path_info = nix_path_infos
        .first()
        .expect("Should have been a first path info");
    let original_signatures = &nix_path_info.signatures;

    tracing::debug!(
        "signing '{}' with key file '{}'",
        store_path.display(),
        secret_key_path
    );
    let mut child = Command::new("nix")
        .args(["--extra-experimental-features", "nix-command"])
        .arg("store")
        .arg("sign")
        .arg("--stdin")
        .args(["--key-file", secret_key_path])
        .arg(&store_path)
        .stdin(Stdio::piped())
        .spawn()?;

    // Take stdin in a scope so it gets dropped (closed) once it goes out of scope
    {
        tracing::debug!("writing store path to `nix store sign`'s stdin");
        let mut stdin = child.stdin.take().expect("Failed to open stdin of child");
        stdin.write_all(store_path.as_os_str().as_bytes()).await?;
    }

    tracing::debug!("waiting for `nix store sign` to finish");
    child.wait().await?;

    // TODO: nix store verify --trusted-public-keys [...] [path]?

    tracing::debug!(
        "extracting current signatures from store path '{}' to compare with original signatures",
        store_path.display()
    );
    let nix_path_info_output = Command::new("nix")
        .args(["--extra-experimental-features", "nix-command"])
        .arg("path-info")
        .arg("--json")
        .arg(&store_path)
        .output()
        .await?;

    let nix_path_infos: Vec<NixPathInfo> = serde_json::from_slice(&nix_path_info_output.stdout)?;
    let nix_path_info = nix_path_infos
        .first()
        .expect("Should have been a first path info");
    let newly_signed_signatures = &nix_path_info.signatures;

    let new_signature = newly_signed_signatures
        .difference(original_signatures)
        .next()
        .expect("Should have only had one new signature");

    // if cfg!(debug_assertions) {
    //     tracing::debug!("removing test path from store and re-adding it");
    //     Command::new("nix-store")
    //         .arg("--delete")
    //         .arg(&store_path)
    //         .stdout(Stdio::null())
    //         .stderr(Stdio::null())
    //         .status()
    //         .await?;
    //     Command::new("nix-store")
    //         .arg("--realise")
    //         .arg(&store_path)
    //         .stdout(Stdio::null())
    //         .stderr(Stdio::null())
    //         .status()
    //         .await?;
    // }

    // FIXME: send back the signed nar now
    Ok(new_signature.to_owned())
}

fn valid_path_info_fingerprint(
    store_path: String,
    base32_nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
) -> String {
    let nar_size_str = nar_size.to_string();
    let references_str = references.join(",");

    let fingerprint = [
        "1;",
        store_path.as_ref(),
        ";",
        base32_nar_hash.as_ref(),
        ";",
        nar_size_str.as_ref(),
        ";",
        references_str.as_ref(),
    ];

    dbg!(fingerprint.into_iter().collect())
}

/*
{
  "dependentRealisations": {
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a496177a9cf410ff61f20015ad!dev": "7h7qgvs4kgzsn8a6rb273saxyqh4jxlz-konsole-18.12.3-dev",
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a696177a9cf410ff61f20015ad!bin": "7h7qgvs4kgzsn8a6rb273saxyqh4jxlz-konsole-18.12.3-bin"
  },
  "id": "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad!out",
  "outPath": "7h7qgvs4kgzsn8a6rb273saxyqh4jxlz-konsole-18.12.3",
  "signatures": [
    "hello",
    "test1234"
  ]
}
*/
#[derive(Debug, Clone, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Realisation {
    dependent_realisations: HashMap<String, String>,
    id: String,
    out_path: String,
    signatures: Vec<String>,
}

#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "camelCase")]
struct RealisationFingerprint {
    dependent_realisations: HashMap<String, String>,
    id: String,
    out_path: String,
}

impl Realisation {
    fn fingerprint(&self) -> RealisationFingerprint {
        RealisationFingerprint {
            dependent_realisations: self.dependent_realisations.clone(),
            id: self.id.clone(),
            out_path: self.out_path.clone(),
        }
    }
}

// test-1:TS12zri2hld72xAwjPUyL0MGqcmbWtHuAFFoRCXu6PwFVd0Awqe4+wgENU7XbWm/itTWumccNX+c7DVFZqKVCA==
async fn sign_realisation(// TODO
    // Json(realisation): Json<Realisation>,
) -> Result<impl IntoResponse> {
    let secret_key_path = "./secret-key"; // FIXME: PathBuf
    let encoded_secret_key = tokio::fs::read_to_string(secret_key_path).await?;

    let Some((key_name, secret_bytes)) = encoded_secret_key.split_once(':') else {
        todo!("???");
    };

    let secret_key_bytes = general_purpose::STANDARD.decode(secret_bytes)?;
    let secret_key: [u8; CRYPTO_SIGN_ED25519_SECRETKEYBYTES] = secret_key_bytes
        .clone()
        .try_into()
        .map_err(|_| color_eyre::eyre::eyre!("secret key wasn't {SECRET_KEY_LENGTH} bytes"))?;

    let fingerprint = valid_path_info_fingerprint(
        String::from("/nix/store/mdi7lvrn2mx7rfzv3fdq3v5yw8swiks6-hello-2.12.1"),
        String::from("sha256:0nhc4jn0g0njfs3ipfcq8jg68f35sm8k67s6pcv8fjm17avcyymi"), // MUST be a Nix base32 hash with the type prefix
        226552,
        vec![
            String::from("/nix/store/aw2fw9ag10wr9pf0qk4nk5sxi0q0bn56-glibc-2.37-8"),
            String::from("/nix/store/mdi7lvrn2mx7rfzv3fdq3v5yw8swiks6-hello-2.12.1"),
        ],
    );
    let mut signature = [0u8; 64];
    dryoc::classic::crypto_sign::crypto_sign_detached(
        &mut signature,
        &fingerprint.as_bytes(),
        &secret_key,
    )?;
    let signature_base64 = general_purpose::STANDARD.encode(signature);

    Ok(format!("{key_name}:{signature_base64}"))
}
