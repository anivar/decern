- **`decern-serve` keeps running when it cannot install its Ctrl-C handler.** The failed install
  resolved the shutdown signal at once, so the server stopped as soon as it started; on Unix it now
  waits for SIGTERM alone, as it already did when the SIGTERM handler failed, and elsewhere, with no
  SIGTERM handler, it runs until it is killed. Authored by @anivar.
