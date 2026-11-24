.PHONY: all build test verify web vet clean

all: build

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

verify:
	go run ./cmd/verify -seeds 1,42,1234 -duration 3600000 -gap 1200

web:
	go run ./cmd/web -addr 127.0.0.1:8099 -seed 42

clean:
	rm -f verify web
