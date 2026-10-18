- **Standing tokens refuse `crit` and honour `nbf`.** A standing token whose header names a
  critical extension is refused, where it was ignored and the token verified — RFC 7515 §4.1.11
  requires the refusal of a recipient that implements no extension. An `nbf` in the future
  refuses the token, and `exp` and `nbf` are read as RFC 7519 NumericDates: a fractional `exp`
  is checked rather than read as missing, an `exp` too large for an unsigned 64-bit integer
  reads as a far expiry where it was refused as missing, and a non-numeric `exp` is refused as
  `standing_token exp is not a number` in place of `standing_token has no exp`. No standing token
  ever changed a decision — a challenge is taken out of the context before the kernel runs — but
  a validly signed one naming a critical extension, or not yet valid, could put a challenge
  answer on the record. Still open: a standing token needs no `typ` (only an access-token `typ`
  is refused), and header parameters that are not critical are ignored, as RFC 7515 §4 requires.
  Authored by @anivar.
