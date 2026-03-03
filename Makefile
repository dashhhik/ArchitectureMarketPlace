.PHONY: generate build test run up down

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
