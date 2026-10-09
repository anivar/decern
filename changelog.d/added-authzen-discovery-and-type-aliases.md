- **AuthZEN discovery, and request types in the PEP's own words.** `decern-serve --public-url
  https://pdp.example` serves `GET /.well-known/authzen-configuration` (AuthZEN 1.0 §9), naming
  the decision point and its evaluation endpoint and nothing the deployment does not serve;
  without the flag the document is 404 rather than assembled from a caller's `Host` header.
  `--authzen-type-alias user=Principal` maps a request's entity types onto the model's, and the
  record carries the model's. `X-Request-ID` comes back on every response (§10.1.3). The
  certification scenario's Basic Core and Discovery sub-levels run as tests against
  `examples/authzen-certification/model`. Authored by @anivar.
