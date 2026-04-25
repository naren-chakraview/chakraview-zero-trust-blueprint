package chakra.authz

import future.keywords.if
import future.keywords.in

# Runtime ext_authz policy — called by Envoy for every request.
# Validates the OBO token chain before allowing traffic to reach the service.
# Decision log fields are picked up by the OTEL Collector filelog receiver.

default allow := false

allow if {
    valid_request
}

# Path 1: direct call (no OBO token) — validate caller is in allow-list
valid_request if {
    not has_obo_token
    caller_in_allow_list
}

# Path 2: delegated call — validate full OBO chain
valid_request if {
    has_obo_token
    valid_obo_token
    caller_in_allow_list
}

has_obo_token if {
    input.attributes.request.http.headers["x-spiffe-obo-token"] != ""
}

caller_in_allow_list if {
    caller := input.attributes.source.principal
    target := input.attributes.destination.principal
    caller in data.spiffe_registry[target].allowed_callers
}

valid_obo_token if {
    token := input.attributes.request.http.headers["x-spiffe-obo-token"]
    [_, payload, _] := io.jwt.decode(token)

    # Signature verification against SPIRE JWKS (loaded as OPA data bundle)
    io.jwt.verify_rs256(token, data.spire_jwks)

    # Audience scope: token must be issued for THIS service
    destination := input.attributes.destination.principal
    destination in payload.aud

    # Subject must match the source principal (no impersonation)
    payload.sub == input.attributes.source.principal

    # Not expired
    time.now_ns() / 1000000000 < payload.exp

    # Chain depth
    chain := object.get(input.attributes.request.http.headers, "x-spiffe-caller-chain", "")
    chain_entries := [e | e := split(chain, ",")[_]; e != ""]
    count(chain_entries) <= data.spiffe_registry[destination].max_obo_chain_depth
}

# Decision log — structured fields for OTEL enrichment
decision_log := {
    "allow": allow,
    "caller": input.attributes.source.principal,
    "destination": input.attributes.destination.principal,
    "obo_present": has_obo_token,
    "obo_chain": object.get(input.attributes.request.http.headers, "x-spiffe-caller-chain", ""),
    "user_principal": object.get(input.attributes.request.http.headers, "x-spiffe-user-principal", ""),
    "trace_id": object.get(input.attributes.request.http.headers, "x-b3-traceid", ""),
    "deny_reason": deny_reason,
}

deny_reason := "caller_not_in_allow_list" if {
    not has_obo_token
    not caller_in_allow_list
}

deny_reason := "obo_token_invalid_audience" if {
    has_obo_token
    token := input.attributes.request.http.headers["x-spiffe-obo-token"]
    [_, payload, _] := io.jwt.decode(token)
    destination := input.attributes.destination.principal
    not destination in payload.aud
}

deny_reason := "obo_chain_depth_exceeded" if {
    has_obo_token
    destination := input.attributes.destination.principal
    chain := object.get(input.attributes.request.http.headers, "x-spiffe-caller-chain", "")
    chain_entries := [e | e := split(chain, ",")[_]; e != ""]
    count(chain_entries) > data.spiffe_registry[destination].max_obo_chain_depth
}

deny_reason := "obo_token_expired" if {
    has_obo_token
    token := input.attributes.request.http.headers["x-spiffe-obo-token"]
    [_, payload, _] := io.jwt.decode(token)
    time.now_ns() / 1000000000 >= payload.exp
}

deny_reason := "none" if {
    allow
}
