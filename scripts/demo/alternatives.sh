#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

admin_token="$(ctx_get '.admin.token')"
seller_token="$(ctx_get '.seller.token')"
user_token="$(ctx_get '.user.token')"
password="$(ctx_get '.password')"
product_id="$(ctx_get '.product_id')"
order_id="$(ctx_get '.order_id')"

rate_limit_minutes="${ORDER_RATE_LIMIT_MINUTES:-5}"
suffix="${DEMO_SUFFIX_ALT:-$(date +%s)}"

log_step "VALIDATION_ERROR: invalid product price"
invalid_product_body='{"name":"Invalid Price Product","price":0,"stock":1,"category":"electronics","status":"ACTIVE"}'
request_json POST "/products" "$seller_token" "$invalid_product_body"
expect_error "400" "VALIDATION_ERROR"
pretty_last

log_step "ACCESS_DENIED: SELLER cannot create orders"
seller_order_body="{\"items\":[{\"product_id\":$product_id,\"quantity\":1}]}"
request_json POST "/orders" "$seller_token" "$seller_order_body"
expect_error "403" "ACCESS_DENIED"
pretty_last

log_step "TOKEN_INVALID: broken access token"
request_json GET "/products?page=0&size=20" "broken.token.value"
expect_error "401" "TOKEN_INVALID"
pretty_last

log_step "REFRESH_TOKEN_INVALID: random refresh token"
refresh_body='{"refresh_token":"INVALID_REFRESH_TOKEN_12345"}'
request_json POST "/auth/refresh" "" "$refresh_body"
expect_error "401" "REFRESH_TOKEN_INVALID"
pretty_last

log_step "INVALID_STATE_TRANSITION: CREATED -> SHIPPED"
state_body='{"status":"SHIPPED"}'
request_json POST "/orders/${order_id}/status" "$admin_token" "$state_body"
expect_error "409" "INVALID_STATE_TRANSITION"
pretty_last

other_user_email="alt_user_${suffix}@example.com"

log_step "Create second USER for ownership and business-error scenarios"
register_body="{\"email\":\"$other_user_email\",\"password\":\"$password\",\"role\":\"USER\"}"
request_json POST "/auth/register" "" "$register_body"
expect_status "201"
pretty_last

login_body="{\"email\":\"$other_user_email\",\"password\":\"$password\"}"
request_json POST "/auth/login" "" "$login_body"
expect_status "200"
pretty_last
other_user_token="$(json_get "$HTTP_BODY" ".access_token")"

log_step "ORDER_OWNERSHIP_VIOLATION: second USER accesses чужой order"
request_json GET "/orders/${order_id}" "$other_user_token"
expect_error "403" "ORDER_OWNERSHIP_VIOLATION"
pretty_last

log_step "INSUFFICIENT_STOCK: quantity above available stock"
insufficient_body="{\"items\":[{\"product_id\":$product_id,\"quantity\":999}]}"
request_json POST "/orders" "$other_user_token" "$insufficient_body"
expect_error "409" "INSUFFICIENT_STOCK"
pretty_last

log_step "PROMO_CODE_INVALID: unknown promo code"
promo_invalid_body="{\"items\":[{\"product_id\":$product_id,\"quantity\":1}],\"promo_code\":\"UNKNOWN_PROMO\"}"
request_json POST "/orders" "$other_user_token" "$promo_invalid_body"
expect_error "422" "PROMO_CODE_INVALID"
pretty_last

log_step "PROMO_CODE_MIN_AMOUNT: subtotal below promo threshold"
high_min_code="MIN_${suffix}"
promo_high_min_body="{\"code\":\"$high_min_code\",\"discount_type\":\"PERCENTAGE\",\"discount_value\":10,\"min_order_amount\":10000,\"max_uses\":100,\"valid_from\":\"2025-01-01T00:00:00Z\",\"valid_until\":\"2030-12-31T23:59:59Z\",\"active\":true}"
request_json POST "/promo-codes" "$seller_token" "$promo_high_min_body"
expect_status "201"
pretty_last

promo_min_body="{\"items\":[{\"product_id\":$product_id,\"quantity\":1}],\"promo_code\":\"$high_min_code\"}"
request_json POST "/orders" "$other_user_token" "$promo_min_body"
expect_error "422" "PROMO_CODE_MIN_AMOUNT"
pretty_last

log_step "Create valid order for second USER"
valid_order_body="{\"items\":[{\"product_id\":$product_id,\"quantity\":1}]}"
request_json POST "/orders" "$other_user_token" "$valid_order_body"
expect_status "201"
pretty_last

log_step "Second immediate create-order attempt (depends on ORDER_RATE_LIMIT_MINUTES=$rate_limit_minutes)"
request_json POST "/orders" "$other_user_token" "$valid_order_body"
if [[ "$rate_limit_minutes" == "0" ]]; then
	expect_error "409" "ORDER_HAS_ACTIVE"
else
	expect_error "429" "ORDER_LIMIT_EXCEEDED"
fi
pretty_last

log_step "Alternative scenarios finished successfully"
