// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
use substrate_egress_extproc::run_main;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_main().await
}
