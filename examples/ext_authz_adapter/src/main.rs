// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Binary entrypoint for decern ext_authz adapter.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ext_authz_adapter::run_main().await
}
