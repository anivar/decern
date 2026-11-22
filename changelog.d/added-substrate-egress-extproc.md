- **Evaluate Agent Substrate actor egress against decern.** A new example,
  `examples/substrate_egress_extproc/`, is an Envoy `ext_proc` service that Agent Substrate's egress
  gateway calls on every outbound request. It reads the verified actor identity and the destination
  and evaluates them against `decern-serve`'s AuthZEN endpoint, in one of two modes: `enforce` blocks
  egress with a 403 on a deny or any failure (fail-closed), and `record` records the decision for the
  subject to contest and never blocks (fail-open, decern off the request path). The decision stays
  separate from the forwarding — the adapter never proxies.
