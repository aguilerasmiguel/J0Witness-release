GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS    = -buildid= -X j0witness/internal/provenance.Version=$(VERSION)
BUILDFLAGS = -trimpath -ldflags "$(LDFLAGS)"

export CGO_ENABLED = 0

.PHONY: build build-all test lint corpus verify-reproducible clean

build:
	$(GO) build $(BUILDFLAGS) -o build/j0witness ./cmd/j0witness

build-all:
	GOOS=linux GOARCH=amd64 $(GO) build $(BUILDFLAGS) -o build/j0witness-linux-amd64 ./cmd/j0witness
	GOOS=linux GOARCH=arm64 $(GO) build $(BUILDFLAGS) -o build/j0witness-linux-arm64 ./cmd/j0witness

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

# Materializa el corpus de laboratorio desde las recetas declarativas.
corpus:
	$(GO) run ./tools/corpusgen -recipes testdata/corpus -out build/corpus

# Principio IV/R9: dos builds en directorios distintos deben dar el mismo hash.
verify-reproducible:
	@rm -rf build/repro-a build/repro-b
	@mkdir -p build/repro-a build/repro-b
	cd build/repro-a && CGO_ENABLED=0 $(GO) build $(BUILDFLAGS) -o j0witness j0witness/cmd/j0witness
	cd build/repro-b && CGO_ENABLED=0 $(GO) build $(BUILDFLAGS) -o j0witness j0witness/cmd/j0witness
	@a=$$(sha256sum build/repro-a/j0witness | cut -d' ' -f1); \
	 b=$$(sha256sum build/repro-b/j0witness | cut -d' ' -f1); \
	 if [ "$$a" = "$$b" ]; then echo "reproducible: $$a"; else echo "NOT reproducible: $$a != $$b"; exit 1; fi

clean:
	rm -rf build
