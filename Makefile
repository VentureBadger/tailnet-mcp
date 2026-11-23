.PHONY: build test lint check

build:
	go build -o bin/tailnet-mcp ./cmd/tailnet-mcp

test:
	go test -race -count=1 ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
	staticcheck ./...

check: lint test
