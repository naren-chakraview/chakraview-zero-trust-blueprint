package chakra.identity.obo

import future.keywords.if
import future.keywords.in

# OBO (On-Behalf-Of) token chain validation policy.
# Loaded as an OPA bundle by both:
#   - The Gatekeeper admission webhook (prevents deploying services without OBO declarations)
#   - The standalone OPA DaemonSet via ext_authz (validates per-request OBO chains)

default allow := false

# Allow if there is no OBO token (direct call — not a delegated request).
# Direct calls are still subject to the SPIFFE principal allow-list in AuthorizationPolicy.
allow if {
    not input.parsed_body
    not input.attributes.request.http.headers["x-spiffe-obo-token"]
    valid_direct_caller
}

# Allow if the OBO token chain is valid.
allow if {
    obo_token := input.attributes.request.http.headers["x-spiffe-obo-token"]
    obo_token != ""
    valid_obo_chain(obo_token)
}

# A direct caller is valid if its SPIFFE ID appears in the target's allow-list.
valid_direct_caller if {
    caller_id := input.attributes.source.principal
    target_id := input.attributes.destination.principal
    caller_id in data.spiffe_registry[target_id].allowed_callers
}

# OBO chain validation:
# 1. JWT signature is valid (verified against SPIRE JWKS bundle)
# 2. Audience matches the destination service's SPIFFE ID
# 3. Subject (immediate caller) is in the destination's allow-list
# 4. Chain depth does not exceed the destination's max_obo_chain_depth
# 5. No chain tampering (simplified: audience scope check)
valid_obo_chain(token) if {
    [_, payload, _] := io.jwt.decode(token)

    # Verify signature using SPIRE trust bundle (loaded as OPA data bundle)
    io.jwt.verify_rs256(token, data.spire_trust_bundle.jwks)

    # Audience must match destination SPIFFE ID
    destination_id := input.attributes.destination.principal
    destination_id in payload.aud

    # Immediate caller (subject) must be allowed
    payload.sub in data.spiffe_registry[destination_id].allowed_callers

    # Chain depth enforcement
    chain := object.get(input.attributes.request.http.headers, "x-spiffe-caller-chain", "")
    chain_depth := count(split(chain, ","))
    max_depth := data.spiffe_registry[destination_id].max_obo_chain_depth
    chain_depth <= max_depth

    # Token must not be expired (io.jwt.decode does not check exp)
    now_ns := time.now_ns()
    now_s := now_ns / 1000000000
    payload.exp > now_s
}

# Deny reasons — used in decision log for OTEL enrichment
deny_reason := "no_obo_token_and_caller_not_in_allow_list" if {
    not input.attributes.request.http.headers["x-spiffe-obo-token"]
    not valid_direct_caller
}

deny_reason := "obo_token_audience_mismatch" if {
    token := input.attributes.request.http.headers["x-spiffe-obo-token"]
    token != ""
    [_, payload, _] := io.jwt.decode(token)
    destination_id := input.attributes.destination.principal
    not destination_id in payload.aud
}

deny_reason := "obo_chain_depth_exceeded" if {
    token := input.attributes.request.http.headers["x-spiffe-obo-token"]
    token != ""
    [_, payload, _] := io.jwt.decode(token)
    destination_id := input.attributes.destination.principal
    chain := object.get(input.attributes.request.http.headers, "x-spiffe-caller-chain", "")
    chain_depth := count(split(chain, ","))
    chain_depth > data.spiffe_registry[destination_id].max_obo_chain_depth
}

deny_reason := "obo_token_expired" if {
    token := input.attributes.request.http.headers["x-spiffe-obo-token"]
    token != ""
    [_, payload, _] := io.jwt.decode(token)
    now_s := time.now_ns() / 1000000000
    payload.exp <= now_s
}
