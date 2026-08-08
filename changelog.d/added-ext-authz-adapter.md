- **An ext_authz HTTP enforcement adapter.** `examples/ext_authz_adapter` is a generic,
  standalone HTTP external authorization shim for `decern-serve`. Translates incoming HTTP
  gateway requests carrying forwarded headers into AuthZEN evaluations, failing closed with
  403 on policy deny or missing subject, and 503 on PDP error, timeout, unreachable PDP,
  or malformed response. Authored by @sameer-kireap.
