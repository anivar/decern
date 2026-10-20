- **The Linux release binaries start.** The static musl builds of `decern` and `decern-serve`
  failed at startup with "entities error: error during entity deserialization". musl reports
  only the part of the main thread's stack mapped so far, and Cedar refuses to evaluate when
  less than 100 KiB seems left. Reproduced on aarch64; the same failure was measured on x86_64
  on a native kernel under a full-system emulator, and x86_64 appeared to work in Docker on
  Apple Silicon only because that emulation gives the main thread a larger stack. Both binaries
  now run startup, and every `decern` command, on a thread with an explicit 8 MiB stack;
  `decern-serve` handles requests on its async runtime's threads, which musl measures
  correctly. The release workflow runs each built binary once, a `decern decide` and one
  `decern-serve` evaluation, before anything is published. Authored by @anivar.
