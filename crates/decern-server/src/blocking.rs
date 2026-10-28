// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The blocking pool's places. Evaluation, the append and its fsync, a search over the
//! directory and an audit over the log are synchronous and run on blocking threads; the pool
//! has as many threads as there are places, every such request takes a place first, and a
//! request that finds none is answered `503` at once rather than waiting in the pool's queue
//! behind a stalled one.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Run a handler's work on a blocking thread and answer with what it returns. Evaluation, the
/// append and its fsync are synchronous; on an executor worker they would hold it, and every
/// request queued behind it, for their whole length, and the request deadline could not fire
/// while they ran. A panic in the work is answered `503` under `error`; whatever it had already
/// recorded stays recorded, and nothing unrecorded is served.
pub(crate) async fn off_the_executor(
    blocking: &Arc<Blocking>,
    error: &'static str,
    work: impl FnOnce() -> Response + Send + 'static,
) -> Response {
    let Some(place) = blocking.take() else {
        return blocking.busy();
    };
    let work = move || {
        let _place = place;
        work()
    };
    match tokio::task::spawn_blocking(work).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": error, "detail": "the request did not complete" })),
        )
            .into_response(),
    }
}

/// How many requests may be on blocking threads at once: the runtime's blocking pool is built
/// this size, every request that runs on it takes a place first, so a request never waits in
/// that pool's queue behind a stalled one, and the next is answered `503` at once. A Mission
/// read (`GET /mission/v1/{s256}`) reads the registry on the executor and takes no place. A stalled store therefore holds at most this many requests'
/// threads, and every request past them is refused now rather than at its deadline.
pub(crate) const MAX_BLOCKING: usize = 512;

/// The places on the blocking pool, each taken for the length of the work it runs: a request
/// that ran out of time keeps its place until its work ends, as its thread is still taken.
pub(crate) struct Blocking {
    cap: usize,
    taken: Arc<AtomicUsize>,
}

/// One place, given back when dropped.
pub(crate) struct Place(Arc<AtomicUsize>);

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Blocking {
    pub(crate) fn new(cap: usize) -> Self {
        Blocking {
            cap,
            taken: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The `503` for a request that found every place taken.
    pub(crate) fn busy(&self) -> Response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "server_busy",
                "detail": format!(
                    "{} requests are already being decided, searched, recorded or audited; \
                     try again",
                    self.cap
                ),
            })),
        )
            .into_response()
    }

    /// A place, or `None` when every one is taken.
    pub(crate) fn take(&self) -> Option<Place> {
        self.taken
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.cap).then_some(n + 1)
            })
            .ok()
            .map(|_| Place(Arc::clone(&self.taken)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Work that panics on its blocking thread is answered 503, never a dropped connection.
    #[tokio::test]
    async fn work_that_panics_off_the_executor_is_answered_503() {
        let blocking = Arc::new(Blocking::new(MAX_BLOCKING));
        let response =
            off_the_executor(&blocking, "decision_unavailable", || panic!("work failed")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Past the cap, a request is refused at once rather than waiting in the pool's queue, and
    /// a place is taken for the length of the work: a request that ran out of time, its future
    /// dropped as the deadline drops it, keeps its place until its work ends, and gives it
    /// back then.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_past_the_blocking_cap_is_refused_at_once() {
        let blocking = Arc::new(Blocking::new(1));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let served = || async {
            off_the_executor(&blocking, "decision_unavailable", || {
                StatusCode::OK.into_response()
            })
            .await
            .status()
        };

        // The request runs out of time while its work is parked on the blocking thread.
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            off_the_executor(&blocking, "decision_unavailable", move || {
                release_rx.recv().unwrap();
                StatusCode::OK.into_response()
            }),
        )
        .await;
        assert!(timed_out.is_err(), "the parked work must still be running");

        let started = std::time::Instant::now();
        let refused = off_the_executor(&blocking, "decision_unavailable", || {
            StatusCode::OK.into_response()
        })
        .await;
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "waited in the queue"
        );
        let body = axum::body::to_bytes(refused.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("server_busy"));

        release_tx.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            served().await,
            StatusCode::OK,
            "the place came back with the work's end"
        );
    }
}
