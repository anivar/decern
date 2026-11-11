- **A control character in a name is refused, and `decern explain` escapes them.** An entity
  type, entity id or action name was bounded in length and recorded as sent, and `decern
  explain` printed recorded values as they were, so a name carrying terminal control sequences
  reached the terminal of whoever read the record. An evaluation, batch item or search whose
  subject, resource or action name holds a control character is now refused (`400`,
  `invalid_request`, nothing recorded). `decern explain` writes every control character in a
  recorded value as its escape, a newline included, which also covers records written before
  this release and the fields the refusal does not reach: the context, a Mission's fields, the
  decision subject. `--json` prints the entry as recorded, where JSON escapes only U+0000 to
  U+001F. Authored by @anivar.
