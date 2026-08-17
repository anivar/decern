- **The sample records in the README and on the site are real again.** The site claimed
  "asserted_by on every record" directly above a record that had none — it was captured
  under `--trust-proxy`, which by design records no caller. The README's record claimed the
  money-gate forbid "fires by name" and showed `"reasons":["F-money"]`; the binary now
  returns an empty `reasons` for that input, because the caller and the resource in the
  example do not exist in the builtin model, so no policy evaluates and the denial comes
  from the Mission requirement instead. Both are replaced with records captured from live
  0.3.x runs — one under bearer validation carrying `asserted_by`, one showing a
  tenant-isolation forbid firing by name with the sponsor resolved. Authored by @anivar.
