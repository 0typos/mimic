.PHONY: all audit audit-caido audit-go build caido check clean coverage fmt-check lab-check release test

VERSION ?= dev
COVERAGE_MIN ?= 80
COVERAGE_GOAL ?= 90

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o mimic ./cmd/mimic

test:
	go test -race ./...

fmt-check:
	@files="$$(gofmt -l $$(find cmd internal lab -type f -name '*.go'))"; \
	if [ -n "$$files" ]; then echo "Go files need gofmt:"; echo "$$files"; exit 1; fi

coverage:
	go test -coverprofile=coverage.out ./...
	@total="$$(go tool cover -func=coverage.out | awk '/^total:/ { gsub("%", "", $$3); print $$3 }')"; \
	awk -v total="$$total" -v minimum="$(COVERAGE_MIN)" -v goal="$(COVERAGE_GOAL)" 'BEGIN { \
		printf "total coverage: %.1f%% (minimum %.1f%%, goal %.1f%%)\n", total, minimum, goal; \
		if (total + 0 < minimum + 0) exit 1 \
	}'

check: fmt-check test coverage
	go vet ./...
	go run ./cmd/mimic validate -config ./config.example.toml

audit: audit-go audit-caido

audit-go:
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

audit-caido:
	cd integrations/caido && corepack pnpm audit --audit-level=high

caido:
	cd integrations/caido && corepack pnpm install --frozen-lockfile && corepack pnpm test && corepack pnpm typecheck && corepack pnpm build

lab-check:
	go test -tags lab ./lab/cmd/lab-origin
	uv lock --script lab/mimic-lab --check
	./lab/mimic-lab --help >/dev/null
	docker compose -f lab/compose.yaml config --quiet
	bash -n lab/start-mimic.sh

release: check audit caido lab-check
	./scripts/build-release.sh "$(VERSION)"

clean:
	go clean
