- **From an adversarial read of the JOSE and CI work.** A bearer token whose header carries
  `"crit": null` is refused like any other `crit`, where `null` read as absent. `decern prove
  --timeout` is described as a bound on the whole run: cvc5 stops itself 60 seconds after it
  starts, so a higher value adds no solver time. Authored by @anivar.
