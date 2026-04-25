# ADR-0008: OpenTelemetry as the Observability Wire

**Status**: Accepted  
**Date**: 2024-05-01  
**Deciders**: Platform security team

---

## Context

A zero-trust architecture generates security-relevant telemetry at every layer:
- SPIRE: SVID issuance rate, rotation failures, attestation denials
- Istio: mTLS coverage, AuthorizationPolicy decisions, connection establishment latency
- OPA: per-request authz decisions, OBO chain validation results, policy evaluation latency
- ZT Gateway: SVID verification overhead, OPA call latency, protocol translation overhead

Correlating these signals across layers requires a single observability wire. If each component ships to its own backend (SPIRE → CloudWatch, Istio → Prometheus, OPA → Splunk), an incident investigation requires switching between tools and manually correlating timestamps.

A single observability pipeline also allows enrichment: the OBO chain from a request can be added to the spans, logs, and metrics for that request — making the chain visible in traces, log queries, and alert annotations.

---

## Decision

Deploy the **OpenTelemetry Collector** as the single observability pipeline. All components ship to the Collector; the Collector routes to backends.

### Component integration

**Envoy (ZT Gateway + Istio sidecars)**

Envoy's native OTEL trace exporter (`envoy.tracers.opentelemetry`) ships traces to the Collector via OTLP/gRPC. Configured in:
- ZT Gateway: `gateway/topology-a-same-pod/envoy-config.yaml` and `gateway/topology-b-dedicated-pod/envoy-bootstrap.yaml`
- Istio mesh: `mesh/telemetry.yaml` (Istio Telemetry API → OTEL Collector)

Trace sampling: 100% on the zero-trust cluster. Every connection is a potential security event; sampling would lose the evidence trail.

Every gateway span includes three custom spans:
- `zt.svid_verification` — attributes: `spiffe.caller_id`, `spiffe.cert_expiry_seconds`, `spiffe.verified` (bool)
- `zt.opa_authz` — attributes: `opa.decision` (allow/deny), `opa.policy`, `obo.chain` (JSON), `opa.latency_ms`
- `zt.protocol_translation` — attributes: `protocol.input`, `protocol.output`, `translation.latency_ms`

**OPA decision logs**

OPA's `decision_logs` plugin writes JSON records to a file. The OTEL Collector's `filelog` receiver tails this file, parses the JSON, and routes records to the log pipeline. The `trace_id` field in each OPA decision record (populated by the `httpjson` lookup from the request's `traceparent` header) links every authz decision to a trace.

**SPIRE metrics**

The SPIRE agent and server expose Prometheus metrics on port 9988. The OTEL Collector's `prometheus` receiver scrapes them and forwards to the metrics pipeline:
- `spire_agent_svid_rotation_total` — rotation frequency
- `spire_agent_attestation_failures_total` → alert threshold: > 5 in 5 minutes
- `spire_server_ca_signing_requests_total` — CA load indicator
- `spire_agent_svid_expire_soon_total` — SVIDs expiring in < 5 minutes (pre-rotation warning)

**OTEL Collector pipeline**

```yaml
receivers:
  otlp:                    # Envoy/Istio traces + metrics, service traces
    protocols:
      grpc: {endpoint: "0.0.0.0:4317"}
  prometheus:              # SPIRE agent/server, OPA health metrics
    config:
      scrape_configs:
        - job_name: spire
          static_configs: [{targets: ["spire-agent:9988", "spire-server:9988"]}]
  filelog:                 # OPA decision logs
    include: ["/var/log/opa/decisions.json"]
    operators:
      - type: json_parser

processors:
  batch: {}
  resource:
    attributes:
      - key: cluster.name
        value: chakra-prod
        action: insert
  transform/obo-enrichment:  # Promote OBO chain fields to first-class span attributes
    trace_statements:
      - context: span
        statements:
          - set(attributes["obo.caller_principal"], attributes["http.request.header.x-spiffe-caller-chain"])
          - set(attributes["obo.user_principal"], attributes["http.request.header.x-spiffe-user-principal"])

exporters:
  otlp/tempo:
    endpoint: "tempo:4317"
  prometheusremotewrite:
    endpoint: "http://mimir:9009/api/v1/push"
  loki:
    endpoint: "http://loki:3100/loki/api/v1/push"
    labels:
      resource:
        - service.name
        - cluster.name
```

### OBO enrichment processor

The `transform/obo-enrichment` processor promotes OBO headers from HTTP request attributes to top-level span attributes. This makes the OBO chain searchable in Tempo without writing a custom Tempo query — filtering on `obo.caller_principal = "spiffe://chakra.internal/ns/orders/sa/orders-svc"` returns all traces involving orders as an OBO delegator.

---

## Dashboards

**`zt-gateway.json`** — ZT gateway performance:
- p50/p95/p99 of `zt.svid_verification` span duration
- p50/p95/p99 of `zt.opa_authz` span duration
- OPA decision rate (allow vs deny) per service
- Protocol translation error rate per translation type

**`zero-trust-overview.json`** — Cluster ZT posture:
- mTLS coverage % (Istio metric: `istio_requests_total{connection_security_policy="mutual_tls"}` / total)
- OBO chain validation failure rate
- SVID rotation health (rotations per hour vs expected)
- Gatekeeper admission denial rate
- SPIRE attestation failure rate

**`zt-traces.json`** — Distributed trace explorer (Grafana + Tempo data source):
- ZT gateway span breakdown per request
- OBO chain visualised per trace (caller → via → target hierarchy)
- Authz decision correlated with trace (OPA decision log linked by trace_id)

---

## Consequences

**Positive:**
- A single trace shows the ZT overhead end-to-end: SVID verification, OPA decision, protocol translation, and the application response time — all in one view.
- OBO chain is visible in traces without a separate audit tool. A security reviewer can answer "who called what on behalf of whom" by looking at a trace.
- The OBO enrichment processor adds the chain as a first-class attribute without modifying any service code.
- Backend independence: switching from Tempo to Jaeger, or from Mimir to Cortex, is a Collector exporter change.

**Negative:**
- 100% trace sampling generates high data volume. At 1000 req/s cluster-wide, Tempo ingestion is ~1000 spans/s × 8 attributes × avg span size. Storage must be sized accordingly; a retention policy of 30 days is recommended.
- The OPA `decision_logs` file must be on a shared volume between the OPA container and the OTEL Collector container (same pod, shared `emptyDir`). This is a pod topology constraint on the OPA DaemonSet.
- The `transform/obo-enrichment` processor assumes OBO headers are present. A request that legitimately has no OBO headers (direct user → service calls) must not trigger a false-positive alert. The processor uses `set(... if IsPresent(...))` to avoid setting empty attributes.

---

## Related

- [ADR-0003](ADR-0003-istio-service-mesh.md) — Istio Telemetry API for trace routing
- [ADR-0006](ADR-0006-zt-gateway-proxy.md) — Envoy tracing configuration in the ZT gateway
- [ADR-0007](ADR-0007-obo-token-model.md) — OBO chain attributes that the enrichment processor promotes
- `observability/otel/collector-config.yaml` — Full OTEL Collector configuration
- `observability/otel/obo-enrichment-processor/config.yaml` — OBO enrichment transform
- `observability/dashboards/zero-trust-overview.json`
- `observability/dashboards/zt-gateway.json`
- `observability/dashboards/zt-traces.json`
