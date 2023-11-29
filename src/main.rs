mod cli;
mod error;
mod nix;
#[cfg(test)]
mod test;
mod trace_layer;

use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use clap::Parser;
use color_eyre::eyre::WrapErr;
use dryoc::classic::crypto_sign_ed25519::Signature;
use dryoc::constants::{
    CRYPTO_SIGN_ED25519_BYTES, CRYPTO_SIGN_ED25519_PUBLICKEYBYTES,
    CRYPTO_SIGN_ED25519_SECRETKEYBYTES,
};
use dryoc::sign::SigningKeyPair;
use serde_derive::Serialize;
use tokio::process::Command;
use tower_http::trace::TraceLayer;

use crate::error::AppError;
use crate::error::Result;

type AppContext = Arc<AppContextInner>;

// FIXME(cole-h): make these proper wrapper types
type NixPublicKey = String;
type NixPrivateKeyPath = PathBuf;
type KeypairMap = HashMap<NixPublicKey, NixPrivateKeyPath>;

struct AppContextInner {
    /// A mapping of public keys to private key paths.
    keypairs: KeypairMap,
}

impl AppContextInner {
    async fn get_secret_contents(secret_key_path: &Path) -> Result<String> {
        let secret_key_path_contents = tokio::fs::read_to_string(&secret_key_path)
            .await
            .wrap_err_with(|| format!("Failed to read {}", secret_key_path.display()))?;

        Ok(secret_key_path_contents.trim().to_owned())
    }

    async fn new(secret_key_paths: Vec<PathBuf>) -> Result<Self> {
        let mut keypairs: HashMap<String, PathBuf> = HashMap::new();

        for secret_key_path in secret_key_paths.into_iter() {
            let secret_key_path_contents = Self::get_secret_contents(&secret_key_path).await?;
            let public_key = secret_key_to_public_key(&secret_key_path_contents)?;
            keypairs.insert(public_key, secret_key_path);
        }

        Ok(Self { keypairs })
    }
}

#[tracing::instrument(skip_all)]
fn secret_key_to_public_key(secret_key_file_contents: &str) -> Result<String> {
    let (key_name, secret_key) = secret_key_from_contents(secret_key_file_contents)?;

    let signing_pair: SigningKeyPair<
        [u8; CRYPTO_SIGN_ED25519_PUBLICKEYBYTES],
        [u8; CRYPTO_SIGN_ED25519_SECRETKEYBYTES],
    > = SigningKeyPair::from_secret_key(secret_key);

    let public_key_base64 = STANDARD.encode(&signing_pair.public_key);
    let public_key = format!("{key_name}:{public_key_base64}");

    Ok(public_key)
}

#[tracing::instrument(skip_all)]
fn secret_key_from_contents(
    secret_key_file_contents: &str,
) -> Result<(String, [u8; CRYPTO_SIGN_ED25519_SECRETKEYBYTES]), error::Report> {
    let Some((key_name, secret_key_bytes_base64)) = secret_key_file_contents.split_once(':') else {
        return Err(AppError::MalformedSecretKey.into());
    };

    let secret_key_bytes = STANDARD.decode(secret_key_bytes_base64)?;
    let secret_key: [u8; CRYPTO_SIGN_ED25519_SECRETKEYBYTES] = secret_key_bytes
        .try_into()
        .map_err(|_| AppError::MalformedSecretKey)?;

    Ok((key_name.to_string(), secret_key))
}

#[tokio::main]
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

    let ctx = AppContextInner::new(cli.secret_key_files).await?;
    let ctx = Arc::new(ctx);

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(trace_layer::trace_layer_make_span_with)
        .on_request(trace_layer::trace_layer_on_request)
        .on_response(trace_layer::trace_layer_on_response);

    let v1 = Router::new()
        .route("/sign", post(sign))
        .route("/sign-store-path", post(sign_store_path))
        .route("/publickey", get(public_key))
        .with_state(ctx.clone());
    let app = Router::new()
        .nest("/_api/v1", v1)
        .fallback(not_found)
        .layer(trace_layer);

    tracing::info!("listening on {}", &cli.bind);
    axum::Server::bind(&cli.bind)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

#[tracing::instrument(skip_all)]
async fn not_found() -> impl IntoResponse {
    (hyper::StatusCode::NOT_FOUND, "Not Found").into_response()
}

#[derive(Serialize)]
struct PublicKeysResponse {
    public_keys: HashSet<String>,
}

#[tracing::instrument(skip_all)]
async fn public_key(State(state): State<AppContext>) -> impl IntoResponse {
    let resp = PublicKeysResponse {
        public_keys: state.keypairs.keys().cloned().collect(),
    };

    Json(resp)
}

#[tracing::instrument(skip_all)]
async fn sign_store_path(
    State(state): State<AppContext>,
    store_path: String,
) -> Result<impl IntoResponse> {
    let store_path = PathBuf::from(store_path);

    if !store_path.exists() {
        return Err(AppError::MissingStorePath(store_path).into());
    }

    tracing::debug!(
        "getting path info from store path '{}'",
        store_path.display()
    );
    let nix_path_info_output = Command::new("nix")
        .args(["--extra-experimental-features", "nix-command"])
        .arg("path-info")
        .arg("--json")
        .arg(&store_path)
        .output()
        .await?;

    let nix_path_infos: Vec<nix::PathInfo> = serde_json::from_slice(&nix_path_info_output.stdout)?;
    let nix_path_info = nix_path_infos
        .first()
        .ok_or_else(|| color_eyre::eyre::eyre!("Should have been a first path info"))?;

    let fingerprint = nix_path_info.fingerprint()?;
    let fingerprint_bytes = Bytes::from(fingerprint);

    let json = sign_fingerprint_with_keys(&fingerprint_bytes, &state.keypairs).await?;

    Ok(json)
}

#[tracing::instrument(skip_all)]
async fn sign(
    State(state): State<AppContext>,
    fingerprint_bytes: bytes::Bytes,
) -> Result<impl IntoResponse> {
    let json = sign_fingerprint_with_keys(&fingerprint_bytes, &state.keypairs).await?;

    Ok(json)
}

#[derive(Serialize)]
struct SignaturesResponse {
    signatures: HashSet<String>,
}

#[tracing::instrument(skip_all)]
async fn sign_fingerprint_with_keys(
    fingerprint_bytes: &bytes::Bytes,
    keypairs: &KeypairMap,
) -> Result<Json<SignaturesResponse>, error::Report> {
    let mut signatures = HashSet::new();

    for secret_key_path in keypairs.values() {
        let encoded_secret_key = AppContextInner::get_secret_contents(&secret_key_path).await?;
        let signature =
            sign_fingerprint_with_secret_key(&fingerprint_bytes, &encoded_secret_key).await?;
        signatures.insert(signature);
    }

    let resp = SignaturesResponse { signatures };

    Ok(Json(resp))
}

// https://github.com/NixOS/nix/blob/ea2f74cbe178d31748d63037e238e3a4a8e02cf3/src/libstore/crypto.cc#L42-L49
#[tracing::instrument(skip_all)]
async fn sign_fingerprint_with_secret_key(
    fingerprint: &bytes::Bytes,
    secret_key_file_contents: &str,
) -> Result<String, error::Report> {
    let (key_name, secret_key) = secret_key_from_contents(secret_key_file_contents)?;

    let mut signature_bytes: Signature = [0u8; CRYPTO_SIGN_ED25519_BYTES];

    dryoc::classic::crypto_sign::crypto_sign_detached(
        &mut signature_bytes,
        &fingerprint,
        &secret_key,
    )?;

    let signature_base64 = STANDARD.encode(signature_bytes);

    Ok(format!("{key_name}:{signature_base64}"))
}
