// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Accepting connections with the bounds `axum::serve` does not set. axum builds hyper's
//! connection without a timer, and hyper applies its header-read timeout only with one, so a
//! client that sends half a request held a connection, and kept a stopping process alive, for
//! as long as it liked.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// How long a client has to send a request's headers, the first request's and each later
/// one's on a kept-alive connection.
pub(crate) const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one request may wait, on its body or on another task, between its headers and
/// its answer. Synchronous work in a handler runs to completion first; the deadline is checked
/// when the handler next waits.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Connections held open at once. HTTP/1 serves one request at a time per connection, so
/// this also bounds the requests in progress.
pub(crate) const MAX_CONNECTIONS: usize = 1024;
/// How long a stopping process waits for requests in progress before it exits.
pub(crate) const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// The bounds [`run`] applies; the constants above in the server, shorter ones in tests.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) header_read: Duration,
    pub(crate) connections: usize,
    pub(crate) shutdown_grace: Duration,
}

pub(crate) const LIMITS: Limits = Limits {
    header_read: HEADER_READ_TIMEOUT,
    connections: MAX_CONNECTIONS,
    shutdown_grace: SHUTDOWN_GRACE,
};

/// Serve `app` on `listener` until `shutdown` resolves, then let requests in progress finish
/// for at most the grace period.
pub(crate) async fn run(
    listener: TcpListener,
    app: Router,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) {
    let graceful = GracefulShutdown::new();
    let slots = Arc::new(Semaphore::new(limits.connections));
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read);
    tokio::pin!(shutdown);
    loop {
        // A slot is taken before accepting, so a full server leaves the next connection in
        // the kernel's backlog rather than accepting it and holding it unanswered.
        let slot = tokio::select! {
            slot = slots.clone().acquire_owned() => match slot {
                Ok(slot) => slot,
                Err(_) => break,
            },
            () = &mut shutdown => break,
        };
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                // Out of descriptors, or a connection reset before it was taken: wait briefly
                // rather than spin on the same error.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let conn =
            builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app.clone()));
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            let _ = conn.await;
            drop(slot);
        });
    }
    let _ = tokio::time::timeout(limits.shutdown_grace, graceful.shutdown()).await;
}

/// The per-request deadline, as a middleware over every route. A request that runs out of
/// time is answered `503`: whatever it was waiting on, its decision was not served. A record
/// already appended stays; only an answer is withheld, never a record skipped.
pub(crate) async fn deadline(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    within(REQUEST_TIMEOUT, next.run(req)).await
}

async fn within(limit: Duration, answer: impl Future<Output = Response>) -> Response {
    match tokio::time::timeout(limit, answer).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "error": "request timed out" })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const SHORT: Limits = Limits {
        header_read: Duration::from_millis(300),
        connections: 1,
        shutdown_grace: Duration::from_millis(300),
    };

    async fn started(
        limits: Limits,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let app = Router::new().route("/", get(|| async { "ok" }));
        let server = tokio::spawn(run(listener, app, limits, async {
            let _ = stopped.await;
        }));
        (addr, stop, server)
    }

    /// Read until the server closes the connection, and say how long that took.
    async fn closed_after(stream: &mut TcpStream) -> Duration {
        let start = Instant::now();
        let mut buf = [0u8; 256];
        while stream.read(&mut buf).await.is_ok_and(|n| n > 0) {}
        start.elapsed()
    }

    #[tokio::test]
    async fn a_half_sent_request_is_dropped_after_the_header_timeout() {
        let (addr, _stop, _server) = started(SHORT).await;
        let mut half = TcpStream::connect(addr).await.unwrap();
        half.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        let waited = tokio::time::timeout(Duration::from_secs(5), closed_after(&mut half))
            .await
            .expect("the server must close a connection whose headers never finish");
        assert!(waited >= Duration::from_millis(200), "{waited:?}");
    }

    #[tokio::test]
    async fn an_idle_kept_alive_connection_is_dropped_after_the_header_timeout() {
        let (addr, _stop, _server) = started(SHORT).await;
        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let n = conn.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
        // The connection stays open for a next request that never comes.
        tokio::time::timeout(Duration::from_secs(5), closed_after(&mut conn))
            .await
            .expect("an idle kept-alive connection must not hold its slot forever");
    }

    #[tokio::test]
    async fn a_full_server_serves_the_next_connection_once_one_closes() {
        let (addr, _stop, _server) = started(SHORT).await;
        // The only slot, held by a client that never finishes its headers.
        let mut holder = TcpStream::connect(addr).await.unwrap();
        holder.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let start = Instant::now();
        let mut next = TcpStream::connect(addr).await.unwrap();
        next.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = String::new();
        tokio::time::timeout(Duration::from_secs(5), next.read_to_string(&mut answer))
            .await
            .expect("the waiting connection is served once the slot frees")
            .unwrap();
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(
            start.elapsed() >= Duration::from_millis(200),
            "served before the holder's slot was released: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_on_a_stalled_client_past_the_grace_period() {
        let (addr, stop, server) = started(Limits {
            header_read: Duration::from_secs(60),
            ..SHORT
        })
        .await;
        let mut half = TcpStream::connect(addr).await.unwrap();
        half.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let start = Instant::now();
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("run must return after the grace period")
            .unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn a_request_past_its_deadline_is_answered_503() {
        let slow = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            "late".into_response()
        };
        let response = within(Duration::from_millis(50), slow).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
