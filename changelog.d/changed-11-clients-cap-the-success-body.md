- **Each client refuses a success body over 1 MiB.** The error body was already capped at 64 KiB and
  the success body was read whole. The TypeScript client counts the body only where the runtime's
  `fetch` gives a stream. Authored by @anivar.
