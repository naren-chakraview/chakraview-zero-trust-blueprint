package chakra.authz_test

import future.keywords.if

# Unit tests for validate-obo-chain.rego
# Run with: opa test policy/opa/ -v

mock_spiffe_registry := {
    "spiffe://chakra.internal/ns/inventory/sa/inventory-svc": {
        "allowed_callers": [
            "spiffe://chakra.internal/ns/orders/sa/orders-svc",
            "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway",
        ],
        "max_obo_chain_depth": 3,
    },
}

# Direct call from an allowed caller — no OBO token required
test_direct_allowed_caller if {
    result := data.chakra.authz.allow with input as {
        "attributes": {
            "source": {"principal": "spiffe://chakra.internal/ns/orders/sa/orders-svc"},
            "destination": {"principal": "spiffe://chakra.internal/ns/inventory/sa/inventory-svc"},
            "request": {"http": {"headers": {}}},
        }
    } with data.spiffe_registry as mock_spiffe_registry
    result == true
}

# Direct call from a disallowed caller
test_direct_disallowed_caller if {
    result := data.chakra.authz.allow with input as {
        "attributes": {
            "source": {"principal": "spiffe://chakra.internal/ns/unknown/sa/unknown"},
            "destination": {"principal": "spiffe://chakra.internal/ns/inventory/sa/inventory-svc"},
            "request": {"http": {"headers": {}}},
        }
    } with data.spiffe_registry as mock_spiffe_registry
    result == false
}

# Chain depth exceeded — should deny
test_chain_depth_exceeded if {
    result := data.chakra.authz.allow with input as {
        "attributes": {
            "source": {"principal": "spiffe://chakra.internal/ns/orders/sa/orders-svc"},
            "destination": {"principal": "spiffe://chakra.internal/ns/inventory/sa/inventory-svc"},
            "request": {"http": {"headers": {
                "x-spiffe-obo-token": "mock-token",
                "x-spiffe-caller-chain": "a,b,c,d",  # depth 4, max is 3
            }}},
        }
    } with data.spiffe_registry as mock_spiffe_registry
      with data.spiffe_jwks as {}
    result == false
}

# Deny reason is populated on rejection
test_deny_reason_caller_not_allowed if {
    result := data.chakra.authz.deny_reason with input as {
        "attributes": {
            "source": {"principal": "spiffe://chakra.internal/ns/unknown/sa/unknown"},
            "destination": {"principal": "spiffe://chakra.internal/ns/inventory/sa/inventory-svc"},
            "request": {"http": {"headers": {}}},
        }
    } with data.spiffe_registry as mock_spiffe_registry
    result == "caller_not_in_allow_list"
}
