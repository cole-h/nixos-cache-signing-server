use std::path::PathBuf;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub type Result<T, E = Report> = color_eyre::eyre::Result<T, E>;

pub struct Report(color_eyre::Report);

impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<E> From<E> for Report
where
    E: Into<color_eyre::Report>,
{
    fn from(value: E) -> Self {
        Self(value.into())
    }
}

impl IntoResponse for Report {
    fn into_response(self) -> axum::response::Response {
        let err = self.0;
        let err_string = format!("{err:?}");

        tracing::error!("{err_string}");

        if let Some(err) = err.downcast_ref::<AppError>() {
            return err.response();
        }

        (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("The Nix secret key file contained an invalid Nix secret key \
        (there was either no `:` separating the name and the Base64-encoded key, or the Base64-encoded key was not exactly 64 bytes)"
    )]
    MalformedSecretKey,

    #[error("Store path '{0}' was missing")]
    MissingStorePath(PathBuf),
}

impl AppError {
    fn response(&self) -> Response {
        match self {
            AppError::MalformedSecretKey => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Something went wront").into_response()
            }
            AppError::MissingStorePath(_) => {
                (StatusCode::BAD_REQUEST, format!("{self}")).into_response()
            }
        }
    }
}
