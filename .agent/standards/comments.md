<!-- SPDX-License-Identifier: Apache-2.0 -->
# Comment standard

Comments ship. In a public repo a comment that describes something not in this
tree is a defect: it misleads readers and can leak the shape of unshipped work.
Every rule below is enforced by `scripts/verify.sh` where a grep can enforce it.

1. **Describe only what ships in THIS repo.** Never name a crate, module, path,
   HTTP route, CLI command, flag, struct, or function that does not exist here.
   No forward references to unbuilt surface. Future direction belongs in
   `ROADMAP.md`, never in code.

2. **Comment the non-obvious WHY, not the WHAT.** If the code already says what
   it does, do not restate it. Explain the reason a choice is load-bearing.

3. **No positioning or marketing language.** Banned in code and doc-comments:
   `moat`, `wedge`, `adoption unlock`, `commercial`, `pitch`, `headline`,
   competitive comparisons. Describe the mechanism, not its market.

4. **Ground standards in ratified specs, not people or coined terms.** Cite an
   RFC/draft by number (e.g. `RFC 8693`) when explaining a standard. Do not
   attribute the design to a named individual as its authority, and do not use
   undefined vocabulary as if canonical — define a term in `docs/` or don't use it.

5. **Honor the honesty bar.** Never write `proven`, `guaranteed`, `tamper-proof`,
   `impossible`, `unbreakable`, or `100%` beyond what the code (or cvc5) actually
   delivers. Where a property is trusted-base rather than machine-checked, say so
   in the same sentence.

6. **No business framing in code.** No pricing, billing, plans, tiers, or
   tenancy-as-revenue in shipped source.

7. **No dangling references.** No "see report", ticket ids, "as discussed",
   dated internal findings, or links to anything not in this repo.

8. **No debt markers or dead code in shipped source.** No `TODO`/`FIXME`/`HACK`/
   `XXX` — open an issue instead. No commented-out code. No snark, no profanity.

Enforcement: `scripts/verify.sh` greps shipped `*.rs`/`*.md`/`*.toml` for a
denylist (non-existent sibling-crate names, marketing terms, debt markers) and
fails CI on a hit — the same mechanism as the lineage guard.
