VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PKG_VERSION ?= $(shell packaging/version.sh)
MAN_DATE ?= $(shell git log -1 --format=%cs 2>/dev/null || date +%Y-%m-%d)
NFPM := go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build test lint docs docs-serve dist man packages test-linux test-cis cis-import stig-import clean

CIS_BENCHMARKS := rhel7 rhel8 rhel9 rhel10 debian11 debian12 debian13 ubuntu18 ubuntu20 ubuntu22 ubuntu24 ubuntu26 suse15 suse16 amazon2 amazon2023 amazon2027
CIS_WINDOWS := win11:Windows-11 win2019:Windows-2019 win2022:Windows-2022 win2025:Windows-2025
STIG_BENCHMARKS := rhel7 rhel8 rhel9 rhel10 ubuntu22 ubuntu24 amazon2023
# DISA STIG packages with the rationale and fix texts, one per STIG benchmark
# (https://public.cyber.mil/stigs/downloads/). Update with new DISA releases.
STIG_DISA := rhel7:U_RHEL_7_V3R15 rhel8:U_RHEL_8_V2R9 rhel9:U_RHEL_9_V2R10 rhel10:U_RHEL_10_V1R3 \
	ubuntu22:U_CAN_Ubuntu_22-04_LTS_V2R10 ubuntu24:U_CAN_Ubuntu_24-04_LTS_V1R7 amazon2023:U_Amazon_Linux_2023_V1R5
STIG_DISA_URL := https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip
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

# Man pages with version and date filled in, compressed for packaging.
man:
	@mkdir -p build/package/man
	@for f in packaging/man/*.[0-9]; do \
		sed -e 's/@VERSION@/$(PKG_VERSION)/' -e 's/@DATE@/$(MAN_DATE)/' $$f | gzip -9 -n > build/package/man/$$(basename $$f).gz; \
	done

# .deb and .rpm packages for linux/amd64 and linux/arm64 in dist/ (static
# binaries, so nothing is distribution specific).
packages: man
	@rm -rf build/package/share && mkdir -p build/package/share dist
	@cp -R cis stig examples build/package/share/
	@find build/package/share -name '*.go' -delete
	@for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '-s -w -X main.version=$(PKG_VERSION)' \
			-o build/package/checkmate ./cmd/checkmate || exit 1; \
		for fmt in deb rpm; do \
			ARCH=$$arch VERSION=$(PKG_VERSION) $(NFPM) package --config packaging/nfpm.yaml --packager $$fmt --target dist/ || exit 1; \
		done; \
	done
	@ls -l dist/*.deb dist/*.rpm

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
	@for w in $(CIS_WINDOWS); do \
		b=$${w%%:*}; repo=$${w#*:}-CIS-Audit; \
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

# Regenerates stig/*.yml from the Ansible Lockdown STIG audit repositories
# (needs gh) and the DISA STIG packages (needs curl and unzip).
stig-import:
	@for b in $(STIG_BENCHMARKS); do \
		repo=$$(echo $$b | tr a-z A-Z)-STIG-Audit; \
		branch=$$(gh api repos/ansible-lockdown/$$repo -q .default_branch); \
		mkdir -p $(CIS_CACHE)/$$b-stig; \
		gh api repos/ansible-lockdown/$$repo/tarball/$$branch | tar xzf - -C $(CIS_CACHE)/$$b-stig --strip-components=1; \
		zip=$$(printf '%s\n' $(STIG_DISA) | sed -n "s/^$$b://p"); \
		[ -n "$$zip" ] || { echo "no DISA package for $$b in STIG_DISA"; exit 1; }; \
		mkdir -p $(CIS_CACHE)/disa; \
		[ -f $(CIS_CACHE)/disa/$$zip.zip ] || curl -fsSL -o $(CIS_CACHE)/disa/$$zip.zip $(STIG_DISA_URL)/$${zip}_STIG.zip || exit 1; \
		xccdf=$$(unzip -Z1 $(CIS_CACHE)/disa/$$zip.zip | grep -m1 'Manual-xccdf\.xml$$'); \
		unzip -oqj $(CIS_CACHE)/disa/$$zip.zip "$$xccdf" -d $(CIS_CACHE)/disa/$$b || exit 1; \
		go run ./tools/cis-import -src $(CIS_CACHE)/$$b-stig -bench $$b-stig \
			-disa $(CIS_CACHE)/disa/$$b/$$(basename "$$xccdf") -out stig/$$b.yml || exit 1; \
	done

# Runs every CIS policy in a container of its platform (needs docker).
test-cis:
	test/linux/run-cis.sh
	test/linux/cis-postgres.sh
	test/linux/cis-apache.sh

clean:
	rm -rf bin build dist site test/linux/out test/linux/out-cis
