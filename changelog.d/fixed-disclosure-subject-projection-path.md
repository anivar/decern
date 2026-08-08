- **The subject-side disclosure names the audit projection the way the route reads it.**
  It advertised `/audit/v1/subject/{handle}` while the route takes `?handle=` — a party
  following the deployment's own pointer got a routing 404 that reads as "no records
  about you". Authored by @anivar.
