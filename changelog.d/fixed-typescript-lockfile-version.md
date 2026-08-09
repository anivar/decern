- **The TypeScript lockfile carries the package version.** `package-lock.json` had missed
  the 0.2.0 bump; both of its version fields now match `package.json`, and the release
  checklist names the lockfile so it cannot be missed again. Authored by @anivar.
