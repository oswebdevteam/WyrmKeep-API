use axum::{
    routing::get,
    Router,
    response::sse::{Event, KeepAlive, Sse},
};
use std::convert::Infallible;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/test", get(test_sse))
        .layer(tower_http::compression::CompressionLayer::new());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8001").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn test_sse() -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, Infallible> {
    let once = tokio_stream::once(Ok(Event::default().data("{\"type\": \"report_ready\"}")));
    Ok(Sse::new(once).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
