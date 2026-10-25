- **The signed-request posture requires `--signed-authority`.** `decern-serve --signed-agent-key`
  no longer starts without `--signed-authority <AUTHORITY>`, this deployment's host and any port
  exactly as its signers' requests carry them, and a signed request whose `@authority` differs is refused
  `401` before any key is consulted. The signature always covered `@authority`, but nothing
  compared it with this deployment, so two deployments trusting the same agent key and audience
  accepted each other's captured requests inside the 60-second freshness window. Add the flag
  with the authority your signers sign for.
  Authored by @anivar.
