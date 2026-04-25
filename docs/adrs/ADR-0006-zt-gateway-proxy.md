# ADR-0006: ZT Gateway Proxy — Envoy Primary, ghostunnel Alternative

**Status**: Accepted  
**Date**: 2024-05-01  
**Deciders**: Platform security team

---

## Context

The Zero-Trust Onboarding Gateway must perform three functions before forwarding a request to a legacy application:

1. **Terminate mTLS** and verify the caller's SPIFFE X.509 SVID
2. **Validate the OBO token chain** via OPA ext_authz
3. **Forward** the request to the legacy application (on loopback in Topology A; to a service pod in Topology B)

Optionally, it must also perform **protocol translation** (HTTP/1.1 → gRPC, plain TCP → mTLS, REST → gRPC).

The proxy component is the performance-critical path. Every legacy application request passes through it. The choice affects: latency overhead, operational complexity, OTEL observability, and protocol support.

---

## Evaluation

| Proxy | SPIFFE native | ext_authz (OPA) | OTEL traces | Protocol translation | Binary size | Notes |
|---|---|---|---|---|---|---|
| **Envoy** | Yes (SDS via SPIRE agent) | Yes (gRPC ext_authz filter) | Yes (OTLP exporter) | HTTP↔gRPC, REST↔gRPC, TCP↔mTLS, WebSocket | ~50MB | Full-featured; xDS for dynamic config |
| **ghostunnel** | Yes (go-spiffe library) | No (external call required) | No (manual instrumentation) | HTTP, TCP only | ~15MB Go binary | Designed for SPIFFE; minimal config |
| tinyproxy | No | No | No | HTTP/1.1 only | <1MB | Requires custom glue for SPIFFE+OPA |
| NGINX/OpenResty | No (manual cert wiring) | Via Lua `auth_request` | Via module | HTTP/1.1, HTTP/2 | ~30MB | Possible but all integrations are custom |
| Caddy | No | Via external auth plugin | Via module | HTTP/1.1, HTTP/2 | ~25MB | Missing native SPIFFE story |

---

## Decision

**Primary: Envoy**

Envoy is chosen because the three gateway functions map directly to Envoy's native filter chain:

1. **SVID verification** — `transport_socket: tls` with SDS (Secret Discovery Service): the SPIRE agent delivers the SVID to Envoy via the SPIFFE Workload API, no manual cert management.
2. **OPA ext_authz** — `envoy.filters.http.ext_authz` with gRPC transport: Envoy calls the local OPA DaemonSet before forwarding. The OBO token check is a native configuration, not custom code.
3. **OTEL tracing** — `envoy.tracers.opentelemetry`: Envoy emits spans to the OTEL Collector with the `zt.svid_verification`, `zt.opa_authz`, and `zt.protocol_translation` span names as custom attributes.

**Topology-specific Envoy config:**

- **Topology A (same-pod)**: Static bootstrap config. One listener on `0.0.0.0:8443` (mTLS), one cluster pointing to `127.0.0.1:<app-port>`. No xDS. Config is a single `envoy-config.yaml` ConfigMap mounted into the gateway container.
- **Topology B (dedicated pod)**: xDS-driven. Bootstrap points to Istiod (or a standalone xDS server). Routes are programmed dynamically — adding a new upstream service requires adding an xDS route entry, not a pod restart.

**Alternative: ghostunnel**

ghostunnel is documented in `gateway/topology-a-same-pod/ghostunnel-alternative/` for teams that:
- Have a same-pod topology only (no Topology B)
- Do not need protocol translation
- Do not need OBO chain validation at the proxy level (using Istio AuthorizationPolicy for runtime authz instead)
- Want the smallest possible footprint (15MB vs 50MB Envoy)

ghostunnel configuration:
```
ghostunnel server \
  --listen 0.0.0.0:8443 \
  --target 127.0.0.1:8080 \
  --spiffe-domain chakra.internal \
  --allow-uri-san "spiffe://chakra.internal/ns/orders/sa/orders-svc"
```

ghostunnel uses `go-spiffe` natively — it fetches its own SVID from the SPIRE agent unix socket and verifies caller SVIDs against the SPIRE trust bundle automatically.

**Limitation vs Envoy**: ghostunnel cannot call OPA ext_authz. OBO chain validation must be performed by the application or by an OPA sidecar that ghostunnel routes through. This is a significant capability gap for the OBO requirement; document clearly in `ghostunnel-alternative/README.md`.

---

## Protocol Translation Catalogue

| Scenario | Envoy filter | Config file |
|---|---|---|
| HTTP/1.1 → mTLS HTTP/2 | `transport_socket: starttls` (downstream plain, upstream mTLS) | `protocol-translation/http1-to-mtls.yaml` |
| REST/JSON → gRPC | `envoy.filters.http.grpc_json_transcoder` (needs `.proto` descriptor) | `protocol-translation/rest-to-grpc.yaml` |
| HTTP/1.1 → gRPC | `envoy.filters.http.grpc_http1_bridge` | `protocol-translation/http1-to-grpc.yaml` |
| Plain TCP → mTLS | TCP proxy filter + downstream `transport_socket: tls` | `protocol-translation/tcp-to-mtls.yaml` |
| WebSocket → HTTP upgrade | `envoy.filters.http.websocket` (upgrade on `Connection: Upgrade`) | `protocol-translation/websocket.yaml` |
| Legacy TLS 1.1/1.2 → SPIFFE mTLS | Downstream TLS with permissive `ssl_protocols`, upstream SPIFFE SDS | `protocol-translation/legacy-tls-upgrade.yaml` |

For non-HTTP protocols (JMS, AMQP, raw TCP), use the TCP proxy filter: Envoy tunnels the bytes in mTLS without protocol understanding. OBO validation is per-connection (on the SVID) rather than per-request (on the JWT).

---

## Consequences

**Positive:**
- Envoy's SDS integration with SPIRE means SVID rotation is transparent — the SPIRE agent pushes a new cert to Envoy via the unix socket; there is no restart or reload.
- OTEL spans from the gateway are structurally identical to Istio sidecar spans — the same Grafana dashboard and Tempo queries work for both.
- The xDS-driven Topology B config supports horizontal scaling: multiple Envoy gateway replicas are configured from the same xDS source.

**Negative:**
- Envoy static config (Topology A) is verbose YAML. A misconfigured filter chain silently fails to route traffic. The `envoy-config.yaml` in this repo is tested with `envoy --mode validate`.
- The `grpc_json_transcoder` filter requires a compiled protobuf file descriptor (`proto_descriptor_bin`). The legacy service's API must have a `.proto` definition for this translation to work; undocumented APIs cannot use REST→gRPC translation.
- Envoy's memory footprint (~50MB base) is significant in Topology A where one Envoy runs per legacy service pod. For clusters with hundreds of legacy pods, ghostunnel's 15MB footprint has meaningful infrastructure cost impact.

---

## Related

- [ADR-0001](ADR-0001-zero-trust-model.md) — Gateway fits in the legacy onboarding extension of the three-plane model
- [ADR-0007](ADR-0007-obo-token-model.md) — OBO token chain that the gateway validates
- [ADR-0008](ADR-0008-observability.md) — OTEL spans emitted by the gateway
- `gateway/topology-a-same-pod/envoy-config.yaml`
- `gateway/topology-b-dedicated-pod/envoy-bootstrap.yaml`
- `gateway/topology-a-same-pod/ghostunnel-alternative/`
