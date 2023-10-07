mod cli;
mod error;
mod nix;
#[cfg(test)]
mod test;
mod trace_layer;

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use clap::Parser;
use color_eyre::eyre::WrapErr;
use dryoc::classic::crypto_sign_ed25519::Signature;
use dryoc::constants::{
    CRYPTO_SIGN_ED25519_BYTES, CRYPTO_SIGN_ED25519_PUBLICKEYBYTES,
    CRYPTO_SIGN_ED25519_SECRETKEYBYTES,
};
use dryoc::sign::SigningKeyPair;
use tokio::process::Command;
use tower_http::trace::TraceLayer;

use crate::error::AppError;
use crate::error::Result;

type AppContext = Arc<AppContextInner>;

struct AppContextInner {
    secret_key_path: PathBuf,
    public_key: String,
}

impl AppContextInner {
    async fn new(secret_key_path: &Path) -> Result<Self> {
        let secret_key_path_contents = tokio::fs::read_to_string(&secret_key_path)
            .await
            .wrap_err_with(|| format!("Failed to read {}", secret_key_path.display()))?;
        let public_key = secret_key_to_public_key(&secret_key_path_contents)?;

        Ok(Self {
            secret_key_path: secret_key_path.to_path_buf(),
            public_key,
        })
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

    let ctx = AppContextInner::new(&cli.secret_key_file).await?;
    let ctx = Arc::new(ctx);

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(trace_layer::trace_layer_make_span_with)
        .on_request(trace_layer::trace_layer_on_request)
        .on_response(trace_layer::trace_layer_on_response);

    let app = Router::new()
        .route("/sign", post(sign))
        .route("/sign-store-path", post(sign_store_path))
        .route("/publickey", get(public_key))
        .with_state(ctx.clone())
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

#[tracing::instrument(skip_all)]
async fn public_key(State(state): State<AppContext>) -> impl IntoResponse {
    state.public_key.clone()
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

    let encoded_secret_key = tokio::fs::read_to_string(&state.secret_key_path)
        .await
        .wrap_err_with(|| format!("Failed to read {}", state.secret_key_path.display()))?;

    let fingerprint = nix_path_info.fingerprint()?;

    sign_fingerprint(&encoded_secret_key, fingerprint.into()).await
}

#[tracing::instrument(skip_all)]
async fn sign(
    State(state): State<AppContext>,
    fingerprint: hyper::body::Bytes,
) -> Result<impl IntoResponse> {
    let encoded_secret_key = tokio::fs::read_to_string(&state.secret_key_path)
        .await
        .wrap_err_with(|| format!("Failed to read {}", state.secret_key_path.display()))?;

    sign_fingerprint(&encoded_secret_key, fingerprint).await
}

// https://github.com/NixOS/nix/blob/ea2f74cbe178d31748d63037e238e3a4a8e02cf3/src/libstore/crypto.cc#L42-L49
#[tracing::instrument(skip_all)]
async fn sign_fingerprint(
    secret_key_file_contents: &str,
    fingerprint: hyper::body::Bytes,
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
