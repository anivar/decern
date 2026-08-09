- **The builtin model names its policies.** Decision reasons and `decern explain` now say
  `P-read` or `F-money` instead of `policy0`-style positions. Records written before this
  change keep the positional ids they were written with — a record is a statement about
  the moment it was made, and renaming it afterwards would be editing history.
  Authored by @anivar.
