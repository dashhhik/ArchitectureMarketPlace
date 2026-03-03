#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

require_cmd docker

log_step "SELECT products"
docker compose exec -T postgres psql -U postgres -d marketplace \
	-c "SELECT id, name, price, stock, category, status, seller_id, created_at, updated_at FROM products ORDER BY id;"

log_step "SELECT orders"
docker compose exec -T postgres psql -U postgres -d marketplace \
	-c "SELECT id, user_id, status, promo_code_id, total_amount, discount_amount, created_at, updated_at FROM orders ORDER BY id;"

log_step "SELECT order_items"
docker compose exec -T postgres psql -U postgres -d marketplace \
	-c "SELECT id, order_id, product_id, quantity, price_at_order FROM order_items ORDER BY id;"

log_step "SELECT promo_codes"
docker compose exec -T postgres psql -U postgres -d marketplace \
	-c "SELECT id, code, discount_type, discount_value, min_order_amount, max_uses, current_uses, valid_from, valid_until, active FROM promo_codes ORDER BY id;"

log_step "SELECT user_operations"
docker compose exec -T postgres psql -U postgres -d marketplace \
	-c "SELECT id, user_id, operation_type, created_at FROM user_operations ORDER BY id;"
