package chakra.authz

# ZT Gateway OBO enforcement — same policy as service-level ext_authz
# but applied at the gateway before the legacy app receives any traffic.
# The legacy app has no awareness of OBO; enforcement is entirely in the gateway.
#
# This file is a symlink-equivalent to policy/opa/policies/validate-obo-chain.rego.
# In the deployed bundle both files are included; the gateway's OPA instance
# loads both and uses the same package. Duplicate default rules are not an issue
# in OPA — the last-defined wins, but since the logic is identical this is harmless.
# In production, use a single bundle source for both gateway and mesh OPA instances.

import future.keywords.if
import future.keywords.in

# Re-export the gateway-specific decision with extra span attributes
# that the OTEL collector's OBO enrichment processor picks up.
gateway_decision := {
    "allow": allow,
    "topology": "zt-gateway",
    "caller_spiffe_id": input.attributes.source.principal,
    "target": input.attributes.destination.principal,
    "obo_chain": object.get(input.attributes.request.http.headers, "x-spiffe-caller-chain", ""),
    "user_principal": object.get(input.attributes.request.http.headers, "x-spiffe-user-principal", ""),
    "trace_id": object.get(input.attributes.request.http.headers, "x-b3-traceid", ""),
    "traceparent": object.get(input.attributes.request.http.headers, "traceparent", ""),
}
