- **An AAuth agent is an agent identifier of the provider that issued its token.** A token's `sub`
  must be `aauth:local@domain` as draft-hardt-oauth-aauth-protocol-11 §5.2 spells it, with `domain`
  the host of the provider named in `iss`; any other `sub` is refused, as is a `parent_agent` that
  is not an agent identifier. Before this, `sub` was taken as sent, so with two providers configured
  either could present the `sub` of the other's agents, including one listed in `--pep`. Under
  `--aauth-provider`, a `--pep` id must be an agent identifier in a configured provider's domain,
  and a provider is named as `https://` and a lowercase host alone (§11.1.1), as is a `ps` claim
  when a token carries one (§5.3.3 step 2), where `https://` with any path was accepted. Authored by
  @anivar.
