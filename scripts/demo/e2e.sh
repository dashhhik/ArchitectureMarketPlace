#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

suffix="${DEMO_SUFFIX:-$(date +%s)}"
password="${DEMO_PASSWORD:-Password123!}"

admin_email="admin_${suffix}@example.com"
seller_email="seller_${suffix}@example.com"
user_email="user_${suffix}@example.com"

log_step "Register users (ADMIN, SELLER, USER)"
for role in ADMIN SELLER USER; do
	case "$role" in
	ADMIN)
		email="$admin_email"
		;;
	SELLER)
		email="$seller_email"
		;;
	USER)
		email="$user_email"
		;;
	esac

	body="{\"email\":\"$email\",\"password\":\"$password\",\"role\":\"$role\"}"
	request_json POST "/auth/register" "" "$body"
	expect_status "201"
	pretty_last

	case "$role" in
	ADMIN)
		admin_id="$(json_get "$HTTP_BODY" ".id")"
		;;
	SELLER)
		seller_id="$(json_get "$HTTP_BODY" ".id")"
		;;
	USER)
		user_id="$(json_get "$HTTP_BODY" ".id")"
		;;
	esac
done

log_step "Login users and collect access tokens"
for role in ADMIN SELLER USER; do
	case "$role" in
	ADMIN)
		email="$admin_email"
		;;
	SELLER)
		email="$seller_email"
		;;
	USER)
		email="$user_email"
		;;
	esac

	body="{\"email\":\"$email\",\"password\":\"$password\"}"
	request_json POST "/auth/login" "" "$body"
	expect_status "200"
	pretty_last

	case "$role" in
	ADMIN)
		admin_token="$(json_get "$HTTP_BODY" ".access_token")"
		;;
	SELLER)
		seller_token="$(json_get "$HTTP_BODY" ".access_token")"
		;;
	USER)
		user_token="$(json_get "$HTTP_BODY" ".access_token")"
		;;
	esac
done

log_step "POST /products (create ACTIVE product)"
product_body='{"name":"Keyboard","description":"Mechanical keyboard","price":120.50,"stock":25,"category":"electronics","status":"ACTIVE"}'
request_json POST "/products" "$seller_token" "$product_body"
expect_status "201"
pretty_last
product_id="$(json_get "$HTTP_BODY" ".id")"

log_step "POST /products (create product for soft delete demo)"
archive_body='{"name":"Old Mouse","description":"Legacy model","price":15.90,"stock":5,"category":"electronics","status":"ACTIVE"}'
request_json POST "/products" "$seller_token" "$archive_body"
expect_status "201"
pretty_last
archive_product_id="$(json_get "$HTTP_BODY" ".id")"

log_step "GET /products/{id}"
request_json GET "/products/${product_id}" "$user_token"
expect_status "200"
pretty_last

log_step "GET /products?page=0&size=20&status=ACTIVE&category=electronics"
request_json GET "/products?page=0&size=20&status=ACTIVE&category=electronics" "$user_token"
expect_status "200"
pretty_last

log_step "PUT /products/{id}"
update_body='{"price":130.75,"stock":30,"description":"Mechanical keyboard v2"}'
request_json PUT "/products/${product_id}" "$seller_token" "$update_body"
expect_status "200"
pretty_last

log_step "DELETE /products/{id} (soft delete -> ARCHIVED)"
request_json DELETE "/products/${archive_product_id}" "$seller_token"
expect_status "200"
pretty_last

promo_code="SALE_${suffix}"
log_step "POST /promo-codes"
promo_body="{\"code\":\"$promo_code\",\"discount_type\":\"PERCENTAGE\",\"discount_value\":10,\"min_order_amount\":100,\"max_uses\":100,\"valid_from\":\"2025-01-01T00:00:00Z\",\"valid_until\":\"2030-12-31T23:59:59Z\",\"active\":true}"
request_json POST "/promo-codes" "$seller_token" "$promo_body"
expect_status "201"
pretty_last
promo_code_id="$(json_get "$HTTP_BODY" ".id")"

log_step "POST /orders"
order_body="{\"items\":[{\"product_id\":$product_id,\"quantity\":2}],\"promo_code\":\"$promo_code\"}"
request_json POST "/orders" "$user_token" "$order_body"
expect_status "201"
pretty_last
order_id="$(json_get "$HTTP_BODY" ".id")"

log_step "GET /orders/{id}"
request_json GET "/orders/${order_id}" "$user_token"
expect_status "200"
pretty_last

log_step "Saving context for next demo scripts: $CTX_FILE"
cat >"$CTX_FILE" <<JSON
{
  "api_url": "$API_URL",
  "password": "$password",
  "admin": {
    "id": $admin_id,
    "email": "$admin_email",
    "token": "$admin_token"
  },
  "seller": {
    "id": $seller_id,
    "email": "$seller_email",
    "token": "$seller_token"
  },
  "user": {
    "id": $user_id,
    "email": "$user_email",
    "token": "$user_token"
  },
  "product_id": $product_id,
  "archive_product_id": $archive_product_id,
  "promo_code_id": $promo_code_id,
  "promo_code": "$promo_code",
  "order_id": $order_id
}
JSON

echo "Context saved to $CTX_FILE"
