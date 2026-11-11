- **The example adapter's PDP deadline covers the response body, and the body is bounded.** The
  external-authorization adapter's `--pdp-timeout-secs` is a deadline over the whole PDP exchange,
  response body included, and a response body over 64 KiB is refused at the bound. The timeout
  covered the request until the PDP's headers arrived; a PDP that then stalled held the adapter's
  request for as long as it liked, and one that streamed a large body was read into memory whole.
  Authored by @anivar.
