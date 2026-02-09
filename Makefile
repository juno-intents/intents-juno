SHELL := /bin/bash

.PHONY: test test-integration

test:
	go test ./...

test-integration:
	go test -tags=integration ./...
