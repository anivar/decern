- **The Python client no longer follows a redirect.** `urllib` re-sends the request headers to the
  redirect target, the bearer token among them. A `3xx` answer is now an error carrying its status
  code. The TypeScript and Go clients still follow redirects with their runtime's defaults, which
  this change did not examine. Authored by @anivar.
