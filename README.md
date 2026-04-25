# Chakra Commerce — Zero-Trust Blueprint

A production-grade reference implementation of zero-trust security for Kubernetes workloads.  
Three enforcement planes working in concert: **Identity** (SPIFFE/SPIRE), **Mesh** (Istio mTLS), **Policy** (OPA/Gatekeeper).  
Centrepiece: a **Zero-Trust Onboarding Gateway** that brings legacy applications into the trust fabric without modifying their code.

---

## What this repo demonstrates

| Concern | What's implemented |
|---|---|
| **Workload identity** | SPIFFE/SPIRE — every pod gets a cryptographic X.509 SVID; no static credentials |
| **Mutual TLS** | Istio `PeerAuthentication STRICT` cluster-wide; all pod-to-pod traffic is mTLS |
| **Default deny** | `NetworkPolicy` (L3/L4) + `AuthorizationPolicy` (L7) — two-layer, explicit allow-list |
| **Policy enforcement** | OPA/Gatekeeper (primary) + Kyverno (documented alternative) |
| **On-Behalf-Of tokens** | OBO token chain validation at every hop — original caller identity preserved end-to-end |
| **Secrets management** | Vault (primary) + AWS Secrets Manager via External Secrets Operator (alternative) |
| **Legacy app onboarding** | Zero-Trust Gateway in two topologies: same-pod loopback isolation + dedicated gateway pod |
| **Protocol translation** | Envoy filters: HTTP/1.1↔gRPC, REST↔gRPC, plain TCP↔mTLS, WebSocket |
| **Distributed tracing** | OTEL Collector wires Envoy + Istio + OPA decision logs; OBO chain visible in every trace |

---

## Architecture: Three Enforcement Planes

```
┌─────────────────────────────────────────────────────────────┐
│  PLANE 1 — IDENTITY (SPIFFE/SPIRE)                          │
│  Every workload gets an X.509 SVID. No SVID = no traffic.   │
│  JWT SVIDs carry OBO chain for inter-service delegation.    │
└──────────────────────┬──────────────────────────────────────┘
                       │ SVIDs issued to
┌──────────────────────▼──────────────────────────────────────┐
│  PLANE 2 — NETWORK (Istio mTLS)                             │
│  PeerAuthentication STRICT (cluster-wide, not per-namespace)│
│  AuthorizationPolicy: default deny, explicit allow-list     │
│  OBO header propagated by EnvoyFilter at every hop          │
└──────────────────────┬──────────────────────────────────────┘
                       │ identity in SVID verified by
┌──────────────────────▼──────────────────────────────────────┐
│  PLANE 3 — POLICY (OPA/Gatekeeper)                          │
│  Admission: no privileged pods, all workloads declare OBO   │
│  Runtime: ext_authz — OPA validates OBO chain per request   │
│  Kyverno: documented alternative for K8s-native teams       │
└─────────────────────────────────────────────────────────────┘
```

---

## Legacy Application Onboarding Gateway

The gateway pattern brings applications into the trust fabric **without modifying their code**.

**Topology A — Same-pod loopback isolation**  
The legacy app container binds only to `127.0.0.1`. The ZT gateway container is the only network-accessible entrypoint. It verifies the caller's SPIFFE SVID and validates the OBO token chain via OPA before forwarding to `127.0.0.1:<app-port>`.

```
[caller] ──mTLS──▶ [zt-gateway:8443] ──SVID verify──▶ OPA
                         │                              │ allow
                         └──────────────────────────────▶ [legacy-app:127.0.0.1:8080]
```

**Topology B — Dedicated gateway pod**  
One gateway pod (horizontally scalable) serves multiple legacy service pods. Services expose no NodePort or LoadBalancer; `NetworkPolicy` restricts ingress to the gateway pod only.

```
[callers] ──mTLS──▶ [zt-gateway-pod] ──verify+OPA──▶ [svc-a-pod:8080]
                         │                          ──▶ [svc-b-pod:8080]
                         │                          ──▶ [svc-c-pod:8080]
```

---

## Repository Map

```
identity/          SPIRE server + agent manifests, SPIFFE ID registry, OBO policy
mesh/              Istio PeerAuthentication, AuthorizationPolicy, OBO EnvoyFilter
policy/            OPA/Gatekeeper policies + Kyverno alternative
secrets/           Vault (primary) + AWS Secrets Manager (alternative)
gateway/           ZT gateway — both topologies, protocol translation, OBO enforcement
observability/     SLOs, OTEL collector, Grafana dashboards, burn-rate alerts
docs/              MkDocs site: ADRs, pattern docs, implementation guides
```

---

## ADRs

| ADR | Decision |
|---|---|
| [ADR-0001](docs/adrs/ADR-0001-zero-trust-model.md) | Three-plane zero-trust model |
| [ADR-0002](docs/adrs/ADR-0002-spiffe-spire.md) | SPIFFE/SPIRE for workload identity |
| [ADR-0003](docs/adrs/ADR-0003-istio-service-mesh.md) | Istio as the mTLS enforcement layer |
| [ADR-0004](docs/adrs/ADR-0004-opa-policy.md) | OPA/Gatekeeper primary, Kyverno alternative |
| [ADR-0005](docs/adrs/ADR-0005-secrets-management.md) | Vault primary, AWS Secrets Manager alternative |
| [ADR-0006](docs/adrs/ADR-0006-zt-gateway-proxy.md) | Envoy primary, ghostunnel alternative for ZT gateway |
| [ADR-0007](docs/adrs/ADR-0007-obo-token-model.md) | On-Behalf-Of token semantics end-to-end |
| [ADR-0008](docs/adrs/ADR-0008-observability.md) | OpenTelemetry as single observability wire |

---

## Key Design Decisions

- **SPIFFE SVID is the identity primitive**, not Kubernetes service accounts or pod IP addresses. Every allow-list references a SPIFFE ID, not a namespace or label selector.
- **OBO semantics are not optional** — any service that accepts traffic from another service must validate that the OBO chain traces back to an authenticated originating principal. `validate-obo-chain.rego` enforces this at admission time.
- **The ZT gateway is not a sidecar mesh replacement** — it coexists with Istio. Istio enforces mTLS and default-deny at the network level. The gateway adds the OBO check and protocol translation layer that Istio cannot do for legacy apps.
- **OTEL traces show the full ZT overhead** — every request through the gateway produces spans for SVID verification, OPA decision, and protocol translation, with the OBO chain as a span attribute. Security audits and performance analysis use the same trace.
