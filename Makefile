VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build test lint docs docs-serve dist test-linux test-cis cis-import clean

CIS_BENCHMARKS := rhel7 rhel8 rhel9 rhel10 debian11 debian12 debian13 ubuntu20 ubuntu22 ubuntu24 ubuntu26 suse15 suse16 amazon2 amazon2023
CIS_CACHE := .cache/cis

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

# Regenerates cis/*.yml from the Ansible Lockdown audit repositories and the
# macOS Security Compliance Project (needs gh).
# The downloaded repositories are kept in $(CIS_CACHE).
cis-import:
	@for b in $(CIS_BENCHMARKS); do \
		repo=$$(echo $$b | tr a-z A-Z)-CIS-Audit; \
		branch=$$(gh api repos/ansible-lockdown/$$repo -q .default_branch); \
		mkdir -p $(CIS_CACHE)/$$b; \
		gh api repos/ansible-lockdown/$$repo/tarball/$$branch | tar xzf - -C $(CIS_CACHE)/$$b --strip-components=1; \
		go run ./tools/cis-import -src $(CIS_CACHE)/$$b -bench $$b -out cis/$$b.yml || exit 1; \
	done
	@for v in sonoma:14 sequoia:15 tahoe:26; do \
		branch=$${v%%:*}; major=$${v#*:}; \
		mkdir -p $(CIS_CACHE)/mscp-$$branch; \
		gh api repos/usnistgov/macos_security/tarball/$$branch | tar xzf - -C $(CIS_CACHE)/mscp-$$branch --strip-components=1; \
		go run ./tools/mscp-import -src $(CIS_CACHE)/mscp-$$branch -macos $$major -out cis/macos$$major.yml || exit 1; \
	done

# Runs every CIS policy in a container of its platform (needs docker).
test-cis:
	test/linux/run-cis.sh
	test/linux/cis-postgres.sh
	test/linux/cis-apache.sh

clean:
	rm -rf bin dist site test/linux/out test/linux/out-cis
