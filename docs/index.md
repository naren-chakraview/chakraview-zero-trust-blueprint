---
title: Chakra Commerce — Zero-Trust Blueprint
description: Production-grade zero-trust reference implementation for Kubernetes workloads.
tags: [overview]
---

# Zero-Trust Blueprint

Three enforcement planes. One identity standard. Complete legacy application onboarding — without modifying the application.

---

## The Three-Plane Model

```mermaid
graph TB
    subgraph PLANE1["PLANE 1 — IDENTITY (SPIFFE/SPIRE)"]
        SPIRE["SPIRE Server\nCA + registration entries"]
        AGENT["SPIRE Agent DaemonSet\nworkload attestation"]
        SVID["X.509 SVID\n1h TTL · auto-rotated"]
        JWT["JWT SVID\n5m TTL · OBO delegation"]
        SPIRE --> AGENT --> SVID
        SPIRE --> AGENT --> JWT
    end

    subgraph PLANE2["PLANE 2 — NETWORK (Istio mTLS)"]
        PA["PeerAuthentication STRICT\ncluster-wide"]
        AP["AuthorizationPolicy\ndefault deny · SPIFFE allow-list"]
        NP["NetworkPolicy\nL3/L4 default deny"]
        OBO_FILTER["EnvoyFilter\nOBO header propagation"]
        PA --- AP --- NP
        OBO_FILTER --- AP
    end

    subgraph PLANE3["PLANE 3 — POLICY (OPA/Gatekeeper)"]
        GK["Gatekeeper\nadmission control"]
        OPA["OPA DaemonSet\next_authz · per-request"]
        OBO_POLICY["validate-obo-chain.rego\nchain depth · audience · TTL"]
        GK --- OPA --- OBO_POLICY
    end

    SVID -->|"consumed by"| PA
    JWT -->|"validated by"| OBO_POLICY
    PLANE1 --> PLANE2 --> PLANE3

    style PLANE1 fill:#dbeafe,color:#1e3a8a,stroke:#93c5fd
    style PLANE2 fill:#d1fae5,color:#064e3b,stroke:#6ee7b7
    style PLANE3 fill:#ede9fe,color:#2e1065,stroke:#c4b5fd

    style SPIRE      fill:#93c5fd,color:#000000,stroke:#3b82f6
    style AGENT      fill:#93c5fd,color:#000000,stroke:#3b82f6
    style SVID       fill:#93c5fd,color:#000000,stroke:#3b82f6
    style JWT        fill:#93c5fd,color:#000000,stroke:#3b82f6

    style PA         fill:#6ee7b7,color:#000000,stroke:#10b981
    style AP         fill:#6ee7b7,color:#000000,stroke:#10b981
    style NP         fill:#6ee7b7,color:#000000,stroke:#10b981
    style OBO_FILTER fill:#6ee7b7,color:#000000,stroke:#10b981

    style GK         fill:#c4b5fd,color:#000000,stroke:#8b5cf6
    style OPA        fill:#c4b5fd,color:#000000,stroke:#8b5cf6
    style OBO_POLICY fill:#c4b5fd,color:#000000,stroke:#8b5cf6
```

Each plane is independently replaceable. A failure in one plane does not bypass the others.

---

## ZT Onboarding Gateway

The centrepiece of this blueprint: bring legacy applications into the trust fabric **without modifying their code**.

=== "Topology A — Same-Pod"
    The legacy app binds only to `127.0.0.1`. The ZT gateway container is the sole network-accessible endpoint.

    ```
    [mTLS caller]
          │
          ▼
    [zt-gateway:8443]  ← SPIRE SDS SVID
          │             ← OPA ext_authz OBO check
          ▼
    [legacy-app:127.0.0.1:8080]
    ```

    **Best for**: Stateful legacy apps, per-instance isolation, smaller deployments.

=== "Topology B — Dedicated Gateway Pod"
    One gateway pod (HPA-scaled) serves multiple legacy service pods. Services expose no external port; `NetworkPolicy` restricts ingress to the gateway pod only.

    ```
    [mTLS callers]
          │
          ▼
    [zt-gateway-pod:8443]  ← xDS-driven routing
          ├──────────────▶ [svc-a-pod:8080]
          ├──────────────▶ [svc-b-pod:8080]
          └──────────────▶ [svc-c-pod:8080]
    ```

    **Best for**: Many legacy services, shared gateway economics, horizontal scale.

---

## On-Behalf-Of Token Chain

Every inter-service call preserves the identity of the originating principal through the full call chain. No service receives the user's session token; each service presents its own SPIFFE identity plus a delegated JWT SVID proving it was authorized by the upstream caller.

```mermaid
sequenceDiagram
    participant U as User
    participant GW as API Gateway
    participant O as Orders
    participant I as Inventory

    U->>GW: HTTP request + session token
    GW->>GW: Validate session → user@chakra.internal
    GW->>GW: Request JWT SVID for Orders (audience: orders-svc)
    GW->>O: Request + X-SPIFFE-OBO-Token (GW→O) + X-SPIFFE-User-Principal
    O->>O: OPA validates OBO: GW allowed → O ✓
    O->>O: Request JWT SVID for Inventory (audience: inventory-svc)
    O->>I: Request + X-SPIFFE-OBO-Token (O→I) + chain: [GW,O]
    I->>I: OPA validates OBO: chain depth ≤ 3 ✓, O in allow-list ✓
    I-->>O: Response
    O-->>GW: Response
    GW-->>U: Response
```

Every OPA decision in this chain is logged with `obo.chain` as a structured field, queryable in Loki and correlated with the Tempo trace by `trace_id`.

---

## OpenTelemetry Integration

Every security event produces a trace span. Every authz decision produces a log record. Both are correlated by `trace_id`.

```mermaid
flowchart LR
    ENV["Envoy\n(ZT Gateway + Istio sidecars)\nOTLP traces"]
    OPA["OPA DaemonSet\nDecision log JSON"]
    SPIRE["SPIRE\nPrometheus metrics"]

    COL["OTEL Collector\nDaemonSet"]

    TEMPO["Grafana Tempo\nTraces"]
    LOKI["Grafana Loki\nLogs"]
    PROM["Mimir\nMetrics"]

    ENV -->|OTLP/gRPC| COL
    OPA -->|filelog| COL
    SPIRE -->|Prometheus scrape| COL

    COL -->|OBO enrichment| TEMPO
    COL -->|trace_id correlation| LOKI
    COL -->|SVID rotation metrics| PROM

    style COL fill:#92400e,color:#fff
    style TEMPO fill:#1e3a5f,color:#fff
    style LOKI fill:#14532d,color:#fff
    style PROM fill:#4a044e,color:#fff
```

The OBO enrichment processor in the OTEL Collector promotes OBO chain headers to first-class span attributes — `obo.caller_principal`, `obo.chain`, `obo.user_principal` — making every request's delegation chain searchable in Tempo without custom instrumentation.

---

## Repository Map

| Directory | What's there |
|---|---|
| [`identity/`](identity/index.md) | SPIRE server + agent manifests, SPIFFE ID registry, OBO policy |
| [`mesh/`](mesh/index.md) | Istio PeerAuthentication, AuthorizationPolicy, OBO EnvoyFilter |
| [`policy/`](policy/index.md) | OPA/Gatekeeper policies + Kyverno alternative |
| [`secrets/`](secrets/index.md) | Vault (primary) + AWS Secrets Manager (alternative) |
| [`gateway/`](gateway/index.md) | ZT gateway — both topologies, protocol translation, OBO enforcement |
| [`observability/`](observability/index.md) | SLOs, OTEL Collector, dashboards, alerts |
| [`docs/adrs/`](adrs/README.md) | 8 ADRs covering every major architectural decision |
