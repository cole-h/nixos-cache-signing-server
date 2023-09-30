use axum::{http::StatusCode, response::IntoResponse};

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

        // if let Some(err) = err.downcast_ref::<SomeErr>() {
        //     return err.response();
        // }

        (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
    }
}
