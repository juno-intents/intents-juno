SHELL := /bin/bash

.PHONY: test test-integration frontend-build build-bridge-api

test:
	go test ./...

test-integration:
	go test -tags=integration ./...

frontend-build:
	cd frontend && npm ci && npm run build

build-bridge-api: frontend-build
	go build -o bin/bridge-api ./cmd/bridge-api
