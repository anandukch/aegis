.PHONY: build run test test-regression test-all docker-up docker-down

build:
	go build ./cmd/server/...

run:
	go run cmd/server/main.go

test:
	go test ./internal/crypto/... ./internal/vault/... -v

test-regression:
	@./tests/run_tests.sh

test-all: test test-regression

docker-up:
	docker-compose up --build -d

docker-down:
	docker-compose down
