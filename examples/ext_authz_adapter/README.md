<!-- SPDX-License-Identifier: Apache-2.0 -->
# ext-authz-adapter

A generic external authorization HTTP adapter for `decern-serve`.

Translates incoming API gateway authorization checks (e.g. NGINX `auth_request`, Traefik `forwardAuth`, HAProxy, or Envoy `ext_authz`) into AuthZEN JSON evaluations against `decern-serve`. Fails closed on deny, PDP error, malformed response, a missing forwarded header, a forwarded header sent more than once, or unreachable PDP. The in-process counterpart is [`../mcp/`](../mcp/README.md) — same decision point, consulted from inside an MCP tool server instead of at the gateway.

---

## Security and the trust boundary

The `--subject-header` flag configures which HTTP header the adapter reads as the caller's verified identity (default: `x-forwarded-subject`).

Whoever can reach the adapter directly can claim to be any subject. This is not a flaw in the design — it is how forward-auth adapters work — but it makes the deployment responsible for something the code cannot enforce:

The API gateway must set that header itself (from verified identity/JWT) and strip any client-supplied copy of it. If the gateway fails to strip client-supplied headers before forwarding to the adapter, the adapter becomes an authentication bypass wearing an authorization decision.

---

## Build and run

```bash
# Build the adapter: its own Cargo project, outside the workspace
cd examples/ext_authz_adapter
cargo build --release

# Run pointing at decern-serve (default PDP address: http://127.0.0.1:8080)
./target/release/ext-authz-adapter --listen-addr 127.0.0.1:9090 --pdp-url http://127.0.0.1:8080
```

---

## CLI options

| Flag | Default | Description |
|---|---|---|
| `--listen-addr` | `127.0.0.1:9090` | Address for the adapter to bind and listen on. |
| `--pdp-url` | `http://127.0.0.1:8080` | Base URL of `decern-serve`; the adapter appends `/access/v1/evaluation`. |
| `--subject-header` | `x-forwarded-subject` | Header carrying the verified subject identity. |
| `--method-header` | `x-forwarded-method` | Header whose value is passed verbatim as `action.name` (`Read`). |
| `--uri-header` | `x-forwarded-uri` | Header carrying the original URI path (`/claims/1`). |
| `--subject-type` | `Principal` | Cedar subject entity type passed to AuthZEN evaluation. |
| `--resource-type` | `Resource` | Cedar resource entity type passed to AuthZEN evaluation. |
| `--pdp-timeout-secs` | `5` | Upstream PDP evaluation request timeout in seconds. |
| `--pdp-bearer-token` | *(none)* | Optional access token for `decern-serve` bearer validation. Prefer `PDP_BEARER_TOKEN` in the environment: an argv value is visible to every user on the host. |

---

## Adapter endpoints

| Endpoint | Method | Purpose | Response |
|---|---|---|---|
| `/healthz` | `GET` | Liveness probe. It does not ask the PDP, so it says nothing about readiness. | `200 OK` (`"ok"`) |
| `/check` | `POST`, `GET` | Authorization check route called by API Gateways. | `200 OK` (allow), `403` (deny), `503` (unavailable) |

---

## Header mapping

| Incoming Gateway Header | AuthZEN Payload Field | Example Value |
|---|---|---|
| Value of `--subject-header` | `subject.id` | `"corp"` |
| Configured `--subject-type` | `subject.type` | `"Principal"` |
| Value of `--method-header` | `action.name` | `"Read"` |
| Value of `--uri-header` | `resource.id` | `"claim1"` |
| Configured `--resource-type` | `resource.type` | `"Resource"` |

The URI header's value is passed verbatim as the resource id — decern matches it against the ids its model declares, so the gateway maps paths to resource ids (`/claims/claim1` → `claim1`) before forwarding, or the model declares path-shaped ids. A value the model has never heard of denies, which is the correct default.

The method header's value is passed verbatim as the action name in the same way. Every gateway example below forwards the HTTP method (`GET`, `POST`), and the builtin model declares no action of that name, so as written each one denies every request: the gateway maps methods to the model's action names before forwarding, or the model declares actions named after methods.

---

## Gateway configuration examples

### NGINX `auth_request`

```nginx
server {
    listen 80;

    location /api/ {
        # 1. Forward authorization check to the ext_authz adapter
        auth_request /_ext_authz;
        auth_request_set $auth_status $upstream_status;

        # 2. Capture response headers returned by the adapter (e.g. x-decern-decision)
        auth_request_set $decern_decision $upstream_http_x_decern_decision;
        proxy_set_header X-Decern-Decision $decern_decision;

        proxy_pass http://upstream_service;
    }

    location = /_ext_authz {
        internal;
        proxy_pass http://127.0.0.1:9090/check;

        # 3. Strip incoming client copy and inject verified subject
        proxy_set_header x-forwarded-subject $remote_user;
        proxy_set_header x-forwarded-method $request_method;
        proxy_set_header x-forwarded-uri $request_uri;

        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
    }
}
```

### Traefik `forwardAuth`

In Traefik, `forwardAuth` sets `X-Forwarded-Method` and `X-Forwarded-Uri` from the request it is checking. With `trustForwardHeader: false` it first removes the client's copies of the X-Forwarded headers Traefik manages itself, and those two are among them. `X-Forwarded-User` and `X-Forwarded-Subject` are not: `authRequestHeaders` passes on whatever the request carries, a client's copy included. An earlier middleware must remove the client's copy and set the verified one, or the client chooses who it is. Point `--subject-header` at whichever of the two that middleware sets:

```yaml
http:
  middlewares:
    decern-authz:
      forwardAuth:
        address: "http://127.0.0.1:9090/check"
        # Forward the verified user header to the adapter
        authRequestHeaders:
          - "X-Forwarded-User"
          - "X-Forwarded-Subject"
          - "Authorization"
        # Receive the decision header back from the adapter
        authResponseHeaders:
          - "X-Decern-Decision"
        # Replaces X-Forwarded-Method and X-Forwarded-Uri with Traefik's own values.
        # Leaves X-Forwarded-User and X-Forwarded-Subject alone: strip those earlier.
        trustForwardHeader: false
```

### Envoy HTTP `ext_authz` filter

Nothing in this repository runs the adapter behind Envoy, so this section states what a configuration must do rather than offering one. Envoy sets none of the three forwarded headers itself, and the filter's `allowed_headers` passes on whatever the request carries, a client's copy included. Ahead of `ext_authz`, something must remove every client copy of all three headers and set them: the subject from verified identity (for example a claim `jwt_authn` verified), the method and URI from the request. Without that the client chooses its subject, its action and its resource, and every decision it records looks well-formed. A route-level `request_headers_to_remove` is not evidence of this on its own: confirm in the Envoy version you run that the removal applies before `ext_authz` reads the headers.

The check request's path is `path_prefix` followed by the original request's path, and the adapter answers only `GET` and `POST` on `/check`, so set `path_override: "/check"` and confirm which method your Envoy sends the check with. Name the three headers in the filter's `allowed_headers`; `authorization_request.allowed_headers` is deprecated.

---

## How it composes with decern-serve caller postures

`decern-serve` requires an explicit caller posture on boot, and names one of five. Two of them suit a gateway, and the adapter supports both.

The other three — `--signed-agent-key`, `--spiffe-trust-domain` and `--aauth-provider` — are *workload* postures: they bind a caller to the principals it may name, so it can only ask about itself. An adapter asks on behalf of everyone behind the gateway, which is the opposite. The adapter presents at most a bearer token, so of the three only `--spiffe-trust-domain` accepts it, with a JWT-SVID as the token. That is useful only when the adapter's SPIFFE ID is listed in `--pep`, and only until the SVID expires: the adapter reads its token once at startup and never refreshes it.

### Standard proxy trust posture (`--trust-proxy`)

When `decern-serve` and `ext-authz-adapter` run side-by-side on a private network or loopback interface (`127.0.0.1`), no bearer token is required on PDP calls:

```bash
# 1. Boot decern-serve declaring proxy trust mode
decern-serve --ledger /tmp/decern.jsonl --addr 127.0.0.1:8080 --trust-proxy

# 2. Boot ext-authz-adapter without a bearer token
ext-authz-adapter --listen-addr 127.0.0.1:9090 --pdp-url http://127.0.0.1:8080
```

### Bearer validation posture (`--bearer-issuer`)

When `decern-serve` requires OAuth 2.1 / RFC 9068 bearer validation (`--bearer-issuer` / `--bearer-audience` / `--bearer-issuer-key`), the adapter acts as the client holding the service access token. Give it the token in `PDP_BEARER_TOKEN` (or `--pdp-bearer-token`, which every user on the host can read from argv):

```bash
# 1. Boot decern-serve with Ed25519 bearer token validation enabled
decern-serve \
  --addr 127.0.0.1:8080 \
  --bearer-issuer https://auth.example.com \
  --bearer-audience https://decern.example.com \
  --bearer-issuer-key "$ISSUER_PUBKEY_HEX"

# 2. Boot ext-authz-adapter presenting the service access token to decern-serve
#    (read from PDP_BEARER_TOKEN, so it stays out of argv)
PDP_BEARER_TOKEN="$SERVICE_ACCESS_TOKEN" ext-authz-adapter \
  --listen-addr 127.0.0.1:9090 \
  --pdp-url http://127.0.0.1:8080
```

---

## Observability and structured logging

The adapter emits single-line, key-value formatted logs to `stderr` without external logging dependencies. Log output is machine-readable and ready for log aggregators (e.g. Datadog, Grafana Loki, AWS CloudWatch):

```text
# Successful authorization evaluation:
check: subject="corp" action="Read" resource="claim1" decision=allow upstream_ms=4

# Policy refusal:
check: subject="attacker" action="Write" resource="claim1" decision=deny upstream_ms=2

# Unauthenticated / Missing subject header:
check: status=403 decision=deny error="missing forwarded header 'x-forwarded-subject'"

# Downstream PDP evaluation failure / timeout:
check_error: subject="corp" action="Read" resource="claim1" error="PDP evaluation request timed out after 5s" upstream_ms=5001
```

---

## Fail-closed contract

The adapter enforces a strict fail-closed contract on every request path:

| Condition | Response Code | Header | Behavior |
|---|---|---|---|
| PDP returns `{"decision": true}` | `200 OK` | `x-decern-decision: allow` | Request allowed by policy. |
| PDP returns `{"decision": false}` | `403 Forbidden` | `x-decern-decision: deny` | Request denied by policy. |
| Missing/empty subject, method, or URI header | `403 Forbidden` | `x-decern-decision: deny` | An incomplete forward is refused, never evaluated under a default. |
| Subject, method, or URI header present more than once | `403 Forbidden` | `x-decern-decision: deny` | No copy can be trusted over another. |
| PDP unreachable / timeout | `503 Service Unavailable` | `x-decern-decision: unavailable` | Fail-closed on network failure. |
| PDP non-2xx (e.g. ledger fail) | `503 Service Unavailable` | `x-decern-decision: unavailable` | Fail-closed on PDP internal error. |
| Malformed JSON body from PDP | `503 Service Unavailable` | `x-decern-decision: unavailable` | Malformed response is never an allow. |
