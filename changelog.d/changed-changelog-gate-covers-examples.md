- **The changelog check covers the example components, not just the crates and SDKs.** It asked
  for a fragment on `crates/` and `sdks/` only, so a behaviour change in `examples/ext_authz_adapter`
  — the forwarded-header refusal in this same release — passed with nothing in the release notes.
  The adapter is a binary people deploy and the MCP example is a server people run, so both now
  need an entry or the `no-changelog` label. Walkthrough scripts, tests, model fixtures, READMEs
  and lockfiles still do not, because none of them changes what a deployment does. Authored by
  @anivar.
