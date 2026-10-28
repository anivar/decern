- **An organization is not an authorization boundary, and the model says so.** The schema's comments
  and the README say that `Organization` membership and parentage are validated at load and read by
  no built-in policy: an organization is not an authorization boundary, `tenant` is. The comments
  called it the tenancy anchor, which implied an isolation the built-in policy does not provide;
  they call it a grouping now. Authored by @anivar.
