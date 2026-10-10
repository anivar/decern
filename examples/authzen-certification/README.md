<!-- SPDX-License-Identifier: Apache-2.0 -->
# AuthZEN certification model

The fixture of the OpenID AuthZEN *Authorization API 1.0* certification scenario
(`openid/authzen`, `certification/authorization-api-1_0-scenario.md`), in decern's vocabulary:
subjects `alice` and `bob`, resources `record-1` (active) and `record-2` (archived), actions `read`, `write` and
`delete`, and decision rules 1–8 — alice owns both records, reads them, writes the active one
and softly deletes them; bob views both, reads them and, being an admin, writes the archived
one; nobody else writes an archived record. Archived and admin are facts the authority records
(`record-2.status`, `bob.roles`) and that a PEP may also describe in `properties`; the policies
read either, so a search finds what an evaluation permits. (The scenario's rule 6 says any
subject described as an admin; this model narrows it to a viewer, so every permit keeps to an
edge the authority graph records and the attenuation-edge proof holds.) A request's `properties`
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
curl -s localhost:8080/access/v1/search/subject -H 'content-type: application/json' -d '{
  "subject":  {"type":"user"},
  "action":   {"name":"read"},
  "resource": {"type":"record","id":"record-1"}
}'
```

The scenario's Basic, Batch and Search levels (Core and Properties) and Discovery run in
`cargo test -p decern-server authzen_certification` against this model. Search returns
every result in one page (pagination is optional in the scenario), and decern has not been
through the OpenID Foundation's certification program.
