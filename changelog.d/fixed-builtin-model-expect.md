- **Fail loudly on a malformed builtin entity graph.** `Model::builtin()` previously
  fell back to a null entity set when its compile-time `entities.json` could not be parsed;
  it now fails at load with a clear message. Added a boot-time warning when the loaded model
  declares actions the server has no scope mapping for, and `X-Content-Type-Options: nosniff`
  on every HTTP response. Authored by @anivar.
