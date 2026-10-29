- **A model whose `revoked` is present and not a boolean is refused at load.** The refusal names the
  principal. It loaded with that principal, and every principal under it, active: the parser read
  any non-boolean as false, and the derived value written over the attribute hid the authored one
  from Cedar's schema check. An absent `revoked` is still false. Authored by @anivar.
