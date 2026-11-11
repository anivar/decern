- **A control character in a name is refused, and `decern explain` escapes them.** An entity type,
  entity id or action name was recorded as sent, and `decern explain` printed recorded values as
  they were, so a name carrying terminal control sequences reached the terminal of whoever read the
  record. An evaluation, batch item or search whose subject, resource or action name holds a control
  character is now refused (`400`, `invalid_request`, nothing recorded). `decern explain` writes
  every control character as its escape, a newline included, in each field it prints, which also
  covers records written before this release and printed fields the refusal does not reach: the
  asserted caller, a Mission's reference, the decision subject. The prose form prints neither the
  context nor a challenge; `--json` prints the whole entry as recorded, where JSON escapes only
  U+0000 to U+001F. Characters that are not control characters, a direction override for one, are
  printed as recorded. Authored by @anivar.
