<!-- SPDX-License-Identifier: Apache-2.0 -->
# ext-authz-adapter

A generic external authorization HTTP adapter for `decern-serve`.

Translates incoming API gateway authorization checks (e.g. NGINX `auth_request`, Traefik `forwardAuth`, HAProxy, or Envoy `ext_authz`) into AuthZEN JSON evaluations against `decern-serve`. Fails closed on deny, PDP error, malformed response, a missing forwarded header, or unreachable PDP.

---

## Security: The Trust Boundary (CRITICAL)

> [!CAUTION]
> **Authentication Bypass Hazard**: The `--subject-header` flag configures which HTTP header the adapter reads as the caller's verified identity (default: `x-forwarded-subject`).
>
> Whoever can reach the adapter directly can claim to be **any subject**. This is not a flaw in the design — it is how forward-auth adapters work — but it makes the deployment responsible for something the code cannot enforce:
>
> **The API gateway MUST set that header itself (from verified identity/JWT) AND strip any client-supplied copy of it.**
>
> If the gateway fails to strip client-supplied headers before forwarding to the adapter, **the adapter becomes an authentication bypass wearing an authorization decision.**

---

## Build and Run

```bash
# Build the adapter standalone binary
cargo build --release

# Run pointing at decern-serve (default PDP address: http://127.0.0.1:8080)
./target/release/ext-authz-adapter --listen-addr 127.0.0.1:9090 --pdp-url http://127.0.0.1:8080
```

---

## CLI Options

| Flag | Default | Description |
|---|---|---|
| `--listen-addr` | `127.0.0.1:9090` | Address for the adapter to bind and listen on. |
| `--pdp-url` | `http://127.0.0.1:8080` | URL of the `decern-serve` PDP evaluation endpoint. |
| `--subject-header` | `x-forwarded-subject` | Header carrying the verified subject identity. |
| `--method-header` | `x-forwarded-method` | Header carrying the original HTTP method (`Read`, `Write`, etc.). |
| `--uri-header` | `x-forwarded-uri` | Header carrying the original URI path (`/claims/1`). |
| `--subject-type` | `Principal` | Cedar subject entity type passed to AuthZEN evaluation. |
| `--resource-type` | `Resource` | Cedar resource entity type passed to AuthZEN evaluation. |
| `--pdp-timeout-secs` | `5` | Upstream PDP evaluation request timeout in seconds. |
| `--pdp-bearer-token` | *(none)* | Optional access token for `decern-serve` bearer validation. Prefer `PDP_BEARER_TOKEN` in the environment: an argv value is visible to every user on the host. |

---

## Adapter Endpoints

| Endpoint | Method | Purpose | Response |
|---|---|---|---|
| `/healthz` | `GET` | Liveness/readiness probe for Kubernetes & Load Balancers. | `200 OK` (`"ok"`) |
| `/check` | `POST`, `GET` | Authorization check route called by API Gateways. | `200 OK` (allow), `403` (deny), `503` (unavailable) |

---

## Header Mapping (Gateway → AuthZEN)

| Incoming Gateway Header | AuthZEN Payload Field | Example Value |
|---|---|---|
| Value of `--subject-header` | `subject.id` | `"corp"` |
| Configured `--subject-type` | `subject.type` | `"Principal"` |
| Value of `--method-header` | `action.name` | `"Read"` |
| Value of `--uri-header` | `resource.id` | `"claim1"` |
| Configured `--resource-type` | `resource.type` | `"Resource"` |

The URI header's value is passed **verbatim** as the resource id — decern matches it against the
ids its model declares, so the gateway maps paths to resource ids (`/claims/claim1` → `claim1`)
before forwarding, or the model declares path-shaped ids. A value the model has never heard of
denies, which is the correct default.

---

## Gateway Configuration Examples

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

        # 3. MUST strip incoming client copy and inject verified subject
        proxy_set_header x-forwarded-subject $remote_user;
        proxy_set_header x-forwarded-method $request_method;
        proxy_set_header x-forwarded-uri $request_uri;

        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
    }
}
```

### Traefik `forwardAuth`

In Traefik, `forwardAuth` automatically forwards original request headers (`X-Forwarded-Method`, `X-Forwarded-Uri`, etc.) to the auth server. To pass a verified subject header (e.g., set by an upstream authentication middleware or OAuth proxy), use `authRequestHeaders` to forward `X-Forwarded-User` or `X-Forwarded-Subject`, or configure `--subject-header x-forwarded-user` on the adapter:

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
        # Traefik strips client-supplied headers from untrusted clients
        trustForwardHeader: false
```

### Envoy HTTP `ext_authz` Filter

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      http_service:
        server_uri:
          uri: "http://127.0.0.1:9090/check"
          cluster: ext_authz_adapter
          timeout: 0.25s
        authorization_request:
          allowed_headers:
            patterns:
              - exact: "x-forwarded-subject"
              - exact: "x-forwarded-method"
              - exact: "x-forwarded-uri"
        authorization_response:
          allowed_upstream_headers:
            patterns:
              - exact: "x-decern-decision"
```

---

## How It Composes With decern-serve Caller Postures (#45 / PR #72)

`decern-serve` requires an explicit caller posture on boot. The adapter supports both postures seamlessly:

### Option A: Standard Proxy Trust Posture (`--trust-proxy`)
When `decern-serve` and `ext-authz-adapter` run side-by-side on a private network or loopback interface (`127.0.0.1`), no bearer token is required on PDP calls:

```bash
# 1. Boot decern-serve declaring proxy trust mode
decern-serve --listen-addr 127.0.0.1:8080 --trust-proxy

# 2. Boot ext-authz-adapter without a bearer token
ext-authz-adapter --listen-addr 127.0.0.1:9090 --pdp-url http://127.0.0.1:8080
```

### Option B: Bearer Validation Posture (`--bearer-issuer`)
When `decern-serve` requires OAuth 2.1 / RFC 9068 bearer validation (`--bearer-issuer` / `--bearer-audience` / `--bearer-issuer-key`), the adapter acts as the client holding the service access token. Pass `--pdp-bearer-token <TOKEN>` to the adapter:

```bash
# 1. Boot decern-serve with Ed25519 bearer token validation enabled (#45)
decern-serve \
  --listen-addr 127.0.0.1:8080 \
  --bearer-issuer https://auth.example.com \
  --bearer-audience https://decern.example.com \
  --bearer-issuer-key z6MkpTHR8VNsBxY...

# 2. Boot ext-authz-adapter presenting the service access token to decern-serve
ext-authz-adapter \
  --listen-addr 127.0.0.1:9090 \
  --pdp-url http://127.0.0.1:8080 \
  --pdp-bearer-token "eyJhbGciOiJFZERTQSI...service_access_token..."
```

---

## Observability and Structured Logging

The adapter emits single-line, key-value formatted logs to `stderr` without external logging dependencies. Log output is machine-readable and ready for log aggregators (e.g. Datadog, Grafana Loki, AWS CloudWatch):

```text
# Successful authorization evaluation:
check: subject=corp action=Read resource=/claims/claim1 decision=allow upstream_ms=4

# Policy refusal:
check: subject=attacker action=Write resource=/claims/claim1 decision=deny upstream_ms=2

# Unauthenticated / Missing subject header:
check: status=403 decision=deny error="missing forwarded header 'x-forwarded-subject'"

# Downstream PDP evaluation failure / timeout:
check_error: subject=corp action=Read resource=/claims/claim1 error="PDP evaluation request timed out after 5s" upstream_ms=5001
```

---

## Fail-Closed Contract

The adapter enforces a strict fail-closed contract on every request path:

| Condition | Response Code | Header | Behavior |
|---|---|---|---|
| PDP returns `{"decision": true}` | `200 OK` | `x-decern-decision: allow` | Request allowed by policy. |
| PDP returns `{"decision": false}` | `403 Forbidden` | `x-decern-decision: deny` | Request denied by policy. |
| Missing/empty subject, method, or URI header | `403 Forbidden` | `x-decern-decision: deny` | An incomplete forward is refused, never evaluated under a default. |
| PDP unreachable / timeout | `503 Service Unavailable` | `x-decern-decision: unavailable` | Fail-closed on network failure. |
| PDP non-2xx (e.g. ledger fail) | `503 Service Unavailable` | `x-decern-decision: unavailable` | Fail-closed on PDP internal error. |
| Malformed JSON body from PDP | `503 Service Unavailable` | `x-decern-decision: unavailable` | Malformed response is never an allow. |
