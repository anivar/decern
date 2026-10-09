<!-- SPDX-License-Identifier: Apache-2.0 -->
# AuthZEN certification model

The fixture of the OpenID AuthZEN *Authorization API 1.0* certification scenario
(`openid/authzen`, `certification/authorization-api-1_0-scenario.md`), in decern's vocabulary:
subjects `alice` and `bob`, resources `record-1` and `record-2`, actions `read`, `write` and
`delete`, and decision rules 1–4 — alice owns both records and may read, write and delete them;
bob is a viewer of `record-1` and may read it, and nothing else. The invariant layer is the
built-in model's, verbatim, so the nine proofs hold over this model too.

```sh
decern prove --model examples/authzen-certification/model

decern-serve --model examples/authzen-certification/model --trust-proxy \
  --authzen-type-alias user=Principal --authzen-type-alias record=Resource \
  --public-url http://localhost:8080 --ledger /tmp/decern-certification.jsonl

curl -s localhost:8080/.well-known/authzen-configuration
curl -s localhost:8080/access/v1/evaluation -H 'content-type: application/json' -d '{
  "subject":  {"type":"user","id":"bob"},
  "action":   {"name":"write"},
  "resource": {"type":"record","id":"record-1"}
}'
```

The scenario's Basic Core and Discovery tests run in
`cargo test -p decern-server authzen_certification` against this model. Basic Properties
(rules 5–8, which need `properties` evaluated), Batch and Search are not implemented, and
decern has not been through the OpenID Foundation's certification program.
