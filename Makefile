# Loads .env if present, otherwise the fake-keyring .env.example, so every
# target works from a fresh clone.
ENV_FILE := $(if $(wildcard .env),.env,.env.example)
WITH_ENV := set -a && . ./$(ENV_FILE) && set +a &&

.PHONY: install build test test-unit test-integration db-up db-down demo vectors keyring ci

install:
	cd ts && npm ci
	cd go && go mod download

build:
	cd ts && npm run build
	cd go && go build ./... && go vet ./...

## Unit + cross-language interop tests (no database needed).
test-unit:
	cd ts && npm test
	cd go && go test ./...

## Postgres integration tests (starts the docker compose database).
test-integration: db-up
	$(WITH_ENV) cd ts && npm run test:integration
	$(WITH_ENV) cd go && go test -count=1 ./...

test: test-unit test-integration

db-up:
	docker compose up -d --wait

db-down:
	docker compose down -v

demo: db-up
	$(WITH_ENV) cd ts && npm run demo

## Regenerates testdata/vectors.json (Node half, then Go half).
vectors:
	./scripts/generate-vectors.sh

## Prints a fresh random keyring. Store it in a secret manager.
keyring:
	@cd ts && npx tsx scripts/generate-keyring.ts

ci: install build test
