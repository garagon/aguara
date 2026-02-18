BINARY := aguara
PKG := github.com/garagon/aguara
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -ldflags "-s -w -X $(PKG)/cmd/aguara/commands.Version=$(VERSION) -X $(PKG)/cmd/aguara/commands.Commit=$(COMMIT)"

.PHONY: build test lint run clean fmt vet

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/aguara

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

run:
	go run ./cmd/aguara $(ARGS)

clean:
	rm -f $(BINARY)
