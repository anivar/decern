- **The Linux release binaries start.** The static aarch64 musl builds of `decern` and
  `decern-serve` failed at startup with "entities error: error during entity deserialization".
  musl reports only the part of the main thread's stack mapped so far, and Cedar refuses to
  evaluate when less than 100 KiB seems left. The cause is not specific to aarch64: the x86_64
  musl builds depend on how large a stack the main thread starts with. Both binaries now run
  their work on a thread with an explicit 8 MiB stack, on every target. The release workflow
  runs each built binary once, a `decern decide` and one `decern-serve` evaluation, before
  anything is published. Authored by @anivar.
