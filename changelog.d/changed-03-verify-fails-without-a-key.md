- **`decern verify` with no `--pubkey` fails.** It checked the hash chain, printed a note that no
  signature was checked, and exited 0, so a script reading the exit code passed a log that
  anyone could have rewritten and rechained. It now exits non-zero and names the two ways on:
  `--pubkey <kid>` for each key that signed the ledger, or the new `--chain-only`, which checks
  the chain alone, says so, and exits 0. `--anchor` now needs `--pubkey`: an anchor whose
  signature is not checked was taken at face value. Add `--chain-only` to a script that meant
  the chain check. `decern explain` without `--pubkey` still exits 0 and says the signature was
  not checked. Authored by @anivar.
