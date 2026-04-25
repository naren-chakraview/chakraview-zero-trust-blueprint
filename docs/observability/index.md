---
title: Observability
description: OpenTelemetry wiring for zero-trust — traces from Envoy, OPA decision logs, SPIRE metrics, OBO chain enrichment.
tags: [observability, otel]
---

# Observability

Every security enforcement event produces a trace span. Every authz decision produces a log record. Both are correlated by `trace_id` in the OTEL Collector.

---

## Signal Sources

| Source | Signal type | Collector receiver | Key attributes |
|---|---|---|---|
| Envoy (ZT gateway + Istio sidecars) | Traces (OTLP) | `otlp` (gRPC 4317) | `zt.svid_verification`, `zt.opa_authz`, `zt.protocol_translation` |
| OPA DaemonSet | Decision logs (JSON) | `filelog` | `allow`, `deny_reason`, `obo_chain`, `trace_id` |
| SPIRE agent | Metrics (Prometheus) | `prometheus` scrape | `spire_agent_svid_rotation_total`, `spire_agent_attestation_failures_total` |
| SPIRE server | Metrics (Prometheus) | `prometheus` scrape | `spire_server_ca_signing_requests_total` |

---

## ZT Gateway Spans

Every request through the ZT gateway produces three child spans within the distributed trace:

```mermaid
gantt
    title ZT Gateway Span Breakdown (example: 4.3ms total)
    dateFormat SSS
    axisFormat %L ms

    section zt.svid_verification
    SPIRE SDS cache hit :0, 0.2ms
    section zt.opa_authz
    OBO chain validate : 0.2ms, 2.1ms
    section zt.protocol_translation
    HTTP/1.1→gRPC bridge : 2.3ms, 0.4ms
    section forward_to_legacy
    Loopback roundtrip : 2.7ms, 1.6ms
```

**`zt.svid_verification`** — SDS cache hit is ~0.2ms. A cache miss (SVID rotation, first request) is ~15ms while the SPIRE agent delivers the new cert.

**`zt.opa_authz`** — OPA DaemonSet on the same node: p99 < 3ms. Remote OPA (across nodes) is 10–20ms. The DaemonSet topology is deliberately chosen to bound this latency.

**`zt.protocol_translation`** — Only present when protocol translation is active. REST→gRPC with JSON transcoder adds ~1ms for protobuf encoding.

---

## OBO Chain in Traces

The OTEL Collector's `transform/obo-enrichment` processor promotes OBO headers to first-class span attributes. No application instrumentation required.

```yaml
# Result: every span in the distributed trace has these searchable attributes
obo.caller_principal: "spiffe://chakra.internal/ns/orders/sa/orders-svc"
obo.chain:            "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway,spiffe://chakra.internal/ns/orders/sa/orders-svc"
obo.user_principal:   "user@chakra.internal"
```

A Tempo query to find all requests where orders-svc acted as an OBO delegator:

```
{ obo.caller_principal = "spiffe://chakra.internal/ns/orders/sa/orders-svc" }
```

---

## OPA Decision Log Correlation

OPA decision logs are tailed by the OTEL Collector `filelog` receiver and forwarded to Loki. Each record includes `trace_id` from the request's `traceparent` header — enabling a jump from a Tempo trace directly to the OPA decision that allowed or denied it.

**Loki query — all OBO chain failures in the last hour:**

```logql
{log_source="opa_decision_log"} | json | deny_reason != "none" | line_format "{{.timestamp}} {{.deny_reason}} caller={{.caller}} target={{.destination}}"
```

**Loki query — trace-correlated OPA decision:**

```logql
{log_source="opa_decision_log"} | json | trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
```

---

## SPIRE Health Metrics

| Metric | Alert threshold | Meaning |
|---|---|---|
| `spire_agent_svid_rotation_total` | < expected rotation rate | Agent stopped rotating SVIDs |
| `spire_agent_attestation_failures_total` | > 5 in 5 minutes | Workload attestation failing (pod identity issue) |
| `spire_agent_svid_expire_soon_total` | > 0 for > 2 minutes | SVIDs not rotating before expiry |
| `spire_server_ca_signing_requests_total` | sudden spike | Large number of pods starting simultaneously |

---

## SLOs

| SLO | Target | Alert |
|---|---|---|
| mTLS coverage | 100% | Any non-mTLS traffic fires `PlaintextTrafficDetected` (critical, 1m) |
| OPA authz deny rate | < 0.01% | `OpaAuthzDenialSpike` (warning, 5m) |
| OBO chain failure rate | < 0.001% | `OboChainFailureSpike` (critical, 2m) |

The mTLS coverage SLO is the most critical: a single non-mTLS connection in steady state indicates either a missing Istio sidecar or a bypassed PeerAuthentication policy.

---

## Reference Implementation

| File | Purpose |
|---|---|
| [`observability/otel/collector-config.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/observability/otel/collector-config.yaml) | Full OTEL Collector pipeline: OTLP + Prometheus + filelog receivers; OBO enrichment processor; Tempo + Mimir + Loki exporters |
| [`observability/slos/mtls-coverage-slo.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/observability/slos/mtls-coverage-slo.yaml) | mTLS coverage SLO + PrometheusRule alert |
| [`observability/slos/policy-violation-slo.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/observability/slos/policy-violation-slo.yaml) | OPA denial rate + OBO chain failure rate SLOs |
