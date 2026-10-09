<!-- SPDX-License-Identifier: Apache-2.0 -->
# AuthZEN certification model

The fixture of the OpenID AuthZEN *Authorization API 1.0* certification scenario
(`openid/authzen`, `certification/authorization-api-1_0-scenario.md`), in decern's vocabulary:
subjects `alice` and `bob`, resources `record-1` and `record-2`, actions `read`, `write` and
`delete`, and decision rules 1–8 — alice owns both records and may read, write and softly delete
them; bob views both and may read them; nobody writes a record the PEP describes as archived,
except a viewer it describes as an admin. (The scenario's rule 6 says any subject described
as an admin; this model narrows it to a viewer, so every permit keeps to an edge the
authority graph records and the attenuation-edge proof holds.) A request's `properties`
reach the policies as
`context.subject`, `context.resource` and `context.action`, where the schema declares them per
action. The invariant layer is the built-in model's, verbatim, so the nine proofs hold over
this model too.

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
curl -s localhost:8080/access/v1/evaluation -H 'content-type: application/json' -d '{
  "subject":  {"type":"user","id":"bob","properties":{"role":"admin"}},
  "action":   {"name":"write"},
  "resource": {"type":"record","id":"record-2","properties":{"status":"archived"}}
}'
curl -s localhost:8080/access/v1/evaluations -H 'content-type: application/json' -d '{
  "subject":  {"type":"user","id":"bob"},
  "resource": {"type":"record","id":"record-1"},
  "evaluations": [{"action":{"name":"read"}}, {"action":{"name":"write"}}]
}'
```

The scenario's Basic and Batch levels (Core and Properties) and Discovery run in
`cargo test -p decern-server authzen_certification` against this model. Search is not
implemented, and decern has not been through the OpenID Foundation's certification program.
