VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build test lint docs docs-serve dist test-linux clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/checkmate ./cmd/checkmate

test:
	go test ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run gofmt -w ." && exit 1)
	go vet ./...

# Regenerates the example pages and builds the site (needs mkdocs-material).
docs:
	go run ./tools/gendocs
	mkdocs build --strict

docs-serve:
	go run ./tools/gendocs
	mkdocs serve

dist:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o dist/checkmate-$$os-$$arch$$ext ./cmd/checkmate || exit 1; \
	done
	@cd dist && (sha256sum checkmate-* 2>/dev/null || shasum -a 256 checkmate-*) > SHA256SUMS

# Runs all examples in Linux containers (needs docker).
test-linux:
	test/linux/run.sh

clean:
	rm -rf bin dist site test/linux/out
