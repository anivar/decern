- **A `challenge_basis` array with a non-string item is a malformed challenge.** Answered `422`, as
  every malformed challenge is. The strings were kept and the rest dropped, so `["ownership", 5]`
  was classified as `["ownership"]`, and only an array with no strings at all was refused. Authored
  by @anivar.
