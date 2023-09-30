use axum::body::BoxBody;
use axum::extract::ConnectInfo;
use axum::response::Response;
use hyper::{Body, Request};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::Span;

pub(crate) fn trace_layer_make_span_with(request: &Request<Body>) -> Span {
    tracing::error_span!("request",
        uri = %request.uri(),
        method = %request.method(),
        // FIXME: doesn't handle X-forwarded-for and friends
        source = request.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|connect_info|
                tracing::field::display(connect_info.ip().to_string()),
            ).unwrap_or_else(||
                tracing::field::display(String::from("<unknown>"))
            ),
        // Fields must be defined to be used, define them as empty if they populate later
        status = tracing::field::Empty,
        latency = tracing::field::Empty,
    )
}

pub(crate) fn trace_layer_on_request(_request: &Request<Body>, _span: &Span) {
    tracing::trace!("Got request")
}

pub(crate) fn trace_layer_on_response(
    response: &Response<BoxBody>,
    latency: Duration,
    span: &Span,
) {
    span.record(
        "latency",
        tracing::field::display(format!("{}μs", latency.as_micros())),
    );
    span.record("status", tracing::field::display(response.status()));
    tracing::trace!("Responded");
}
