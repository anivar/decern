- **`decern-serve` bounds what one client can make it hold.** A request's headers must arrive
  within 10 seconds, the idle wait on a kept-alive connection included, and a request still
  waiting on its body after 30 seconds is answered `503`; a ledger append already under way
  finishes first. At most 1,024 connections are held at once, and a stopping server waits 30
  seconds for requests in progress, where a client that sent half a request could keep a
  connection, and a stopping process, alive indefinitely. `Signature` is bounded at 8 KiB like the
  other signature headers, and a repeated label is found without comparing every pair, where a
  large header cost seconds of work before any key was consulted. An entity type, entity id or
  action name over 1 KiB is refused with `413 name_too_large`, and a batch that would record more
  than 16 MiB, its defaults counted once per item that inherits them, is refused whole with `413
  batch_too_large` before anything is recorded; one 123 KB batch could record 120 MB. Bearer and
  SPIFFE callers are authenticated before the body is read, so a caller with no credential is
  refused without the server waiting on its body. An error that quotes the request is cut to 512
  characters in the answer. Authored by @anivar.
