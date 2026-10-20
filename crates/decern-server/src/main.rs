// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! decern-serve — a thin PDP: every decision is proven-model-evaluated AND recorded before it is served.

mod aauth;
mod args;
mod audit;
/// The AuthZEN 1.0 certification scenario — every level, and Discovery — driven end to end
/// against the certification model in `examples/authzen-certification/model`.
#[cfg(test)]
mod authzen_certification;
mod batch;
mod bearer;
mod boot;
mod caller;
mod challenge;
mod decide;
mod deployment;
mod discovery;
mod httpsig;
mod jose;
mod mission;
mod record;
mod routes;
mod search;
mod sig;
mod spiffe;
mod state;
#[cfg(test)]
mod testutil;

use anyhow::{Context, Result};
use boot::serve;

pub(crate) use state::{AppState, LedgerBackend, caller_disclosure, now_secs};

fn main() -> Result<()> {
    // On a thread with the stack Cedar needs, not the main thread: see
    // `decern_kernel::with_evaluation_stack`.
    decern_kernel::with_evaluation_stack("decern-serve", || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("starting the async runtime")?
            .block_on(serve())
    })
    .context("starting the main thread")?
}
