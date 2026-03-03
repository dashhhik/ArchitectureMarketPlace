.PHONY: generate build test run up down demo-up demo-down demo-wait demo-e2e demo-alt demo-db demo-logs demo-all

generate:
	go generate ./...

build: generate
	go build ./...

test: generate
	go test ./...

run: generate
	go run ./cmd/marketplace

up:
	docker compose up --build

down:
	docker compose down -v

demo-up:
	docker compose up -d --build

demo-down:
	docker compose down -v

demo-wait:
	bash scripts/demo/wait.sh

demo-e2e:
	bash scripts/demo/e2e.sh

demo-alt:
	bash scripts/demo/alternatives.sh

demo-db:
	bash scripts/demo/db-selects.sh

demo-logs:
	docker compose logs --tail=200 marketplace-service

demo-all: demo-up demo-wait demo-e2e demo-alt demo-db
