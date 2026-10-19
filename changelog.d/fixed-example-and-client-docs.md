- **Example and client docs corrected where following them would mislead.** The gateway
  adapter's Traefik example no longer says Traefik strips a client's `X-Forwarded-Subject`:
  `trustForwardHeader: false` resets only the headers Traefik manages, so an earlier middleware
  must strip and set the subject. The Envoy example, which also let a client choose its method
  and URI, is replaced by what a configuration must do. The adapter README says every gateway
  example forwards the HTTP method as the action name, which the builtin model does not
  declare, that `--pdp-url` takes the base URL, and that a forwarded header sent twice is a
  403. The MCP example says its server approves a Mission in `corp`'s name rather than relaying
  an approval claim. The AAuth example says a conformant draft -11 agent is refused. The
  client READMEs say `context` reaches the policies wherever the schema declares it, rather
  than calling it advisory, and that `reasons` names the deciding forbid policies on a deny.
  The Postgres store README no longer claims a money-budget gate, says the Mission registry
  stays a per-host file under `--sharded postgres://`, and says `decern-serve` built with
  `--features postgres` does carry its TLS stack. Authored by @anivar.
