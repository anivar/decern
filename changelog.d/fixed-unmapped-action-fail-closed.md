- **Unmapped actions deny without a Mission.** An action the server has no scope mapping
  for previously proceeded without any Mission check when `--require-mission` was off,
  letting caller-supplied approval flags ride through unsupervised. It now denies with a
  clear reason, matching the behaviour `MoveMoney` already had. Authored by @anivar.
