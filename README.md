# Marketplace API (Go + Gin)

Сервис маркетплейса, реализованный в стиле OpenAPI-first на `Go` + `Gin` + `PostgreSQL`.

## Что реализовано

- `OpenAPI` спецификация: `src/main/resources/openapi/openapi.yaml`
- Генерация серверного контракта и DTO из OpenAPI (`go generate ./...`)
- CRUD для `products` с мягким удалением (`ARCHIVED`)
- JWT авторизация (`access` + `refresh`)
- Роли: `USER`, `SELLER`, `ADMIN`
- Транзакционная бизнес-логика для `orders`
- Промокоды и перерасчет стоимости заказа
- Контрактные ошибки с `error_code`
- JSON-логирование API с `request_id` и `X-Request-Id`
- PostgreSQL + Flyway миграции

## Структура

- `cmd/marketplace/main.go` — запуск API
- `internal/app` — middleware, хендлеры, бизнес-логика
- `internal/api` — generated API-контракт (DTO + роутинг)
- `internal/db/migrations` — Flyway SQL миграции
- `src/main/resources/openapi/openapi.yaml` — контракт API

## Генерация кода

```bash
go generate ./...
```

Сгенерированный файл: `internal/api/openapi.gen.go` (в `.gitignore`).

## Запуск в Docker

```bash
docker compose up --build
```

Сервисы:

- API: `http://localhost:8000`
- PostgreSQL: `localhost:5432`
- Flyway применяется автоматически перед запуском API

## Базовый E2E сценарий для защиты

1. Поднять систему:

```bash
docker compose up --build
```

2. Зарегистрировать пользователей:

```bash
curl -sS -X POST http://localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"Password123","role":"ADMIN"}'

curl -sS -X POST http://localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"seller@example.com","password":"Password123","role":"SELLER"}'

curl -sS -X POST http://localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"Password123","role":"USER"}'
```

3. Логин (получить токены):

```bash
ADMIN_TOKEN=$(curl -sS -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"Password123"}' | jq -r .access_token)

SELLER_TOKEN=$(curl -sS -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"seller@example.com","password":"Password123"}' | jq -r .access_token)

USER_TOKEN=$(curl -sS -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"Password123"}' | jq -r .access_token)
```

4. Создать товар от имени `SELLER`:

```bash
PRODUCT_ID=$(curl -sS -X POST http://localhost:8000/products \
  -H "Authorization: Bearer $SELLER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Keyboard","description":"Mechanical","price":120.50,"stock":25,"category":"electronics","status":"ACTIVE"}' | jq -r .id)
```

5. Получить список товаров:

```bash
curl -sS "http://localhost:8000/products?page=0&size=20&status=ACTIVE&category=electronics" \
  -H "Authorization: Bearer $USER_TOKEN"
```

6. Создать промокод:

```bash
curl -sS -X POST http://localhost:8000/promo-codes \
  -H "Authorization: Bearer $SELLER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"code":"SALE10","discount_type":"PERCENTAGE","discount_value":10,"min_order_amount":100,"max_uses":100,"valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-12-31T23:59:59Z","active":true}'
```

7. Создать заказ:

```bash
ORDER_ID=$(curl -sS -X POST http://localhost:8000/orders \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"items\":[{\"product_id\":$PRODUCT_ID,\"quantity\":2}],\"promo_code\":\"SALE10\"}" | jq -r .id)
```

8. Показать заказ:

```bash
curl -sS http://localhost:8000/orders/$ORDER_ID -H "Authorization: Bearer $USER_TOKEN"
```

9. Показать данные в БД (`SELECT`):

```bash
docker compose exec postgres psql -U postgres -d marketplace -c "SELECT id, name, stock, status, seller_id FROM products ORDER BY id;"
docker compose exec postgres psql -U postgres -d marketplace -c "SELECT id, user_id, status, total_amount, discount_amount, promo_code_id FROM orders ORDER BY id;"
docker compose exec postgres psql -U postgres -d marketplace -c "SELECT id, order_id, product_id, quantity, price_at_order FROM order_items ORDER BY id;"
docker compose exec postgres psql -U postgres -d marketplace -c "SELECT id, code, current_uses, max_uses, active FROM promo_codes ORDER BY id;"
```

## Альтернативные проверки (для защиты)

- Валидация: `price <= 0`, `quantity = 0`, `promo_code` с неверным pattern -> `VALIDATION_ERROR`
- Нехватка остатков -> `INSUFFICIENT_STOCK` + details
- Повторное создание заказа слишком быстро -> `ORDER_LIMIT_EXCEEDED`
- Второй активный заказ у пользователя -> `ORDER_HAS_ACTIVE`
- Обновление/отмена из недопустимого статуса -> `INVALID_STATE_TRANSITION`
- SELLER пытается создать заказ -> `ACCESS_DENIED`
- USER пытается редактировать чужой заказ -> `ORDER_OWNERSHIP_VIOLATION`
- Просроченный/невалидный access token -> `TOKEN_EXPIRED` / `TOKEN_INVALID`
- Невалидный refresh token -> `REFRESH_TOKEN_INVALID`

## Примечания

- В обычной среде нужно выполнить:

```bash
go mod tidy
go generate ./...
go test ./...
```
