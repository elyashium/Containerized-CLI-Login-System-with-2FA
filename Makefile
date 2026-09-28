# Convenience wrapper around docker compose and the Go toolchain.
# Everything here is optional — the README lists the equivalent raw commands.

SHELL := /bin/sh
COMPOSE ?= docker compose
VERSION ?= 1.0.0

.DEFAULT_GOAL := help

# ---------------------------------------------------------------- docker flow

.PHONY: help
help: ## Show this help
	@echo "Containerized CLI Login System"
	@echo
	@echo "Quick start:"
	@echo "  make setup    generate .env with a fresh encryption key"
	@echo "  make up       start the database"
	@echo "  make cli      open the login shell"
	@echo
	@echo "Targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: .env build ## Create .env with a generated encryption key, then build
	@if grep -q '^APP_ENCRYPTION_KEY=.\+' .env; then \
		echo "APP_ENCRYPTION_KEY already set in .env — leaving it alone."; \
	else \
		key=$$($(COMPOSE) run --rm --no-deps -T cli genkey | tr -d '\r\n'); \
		if [ -z "$$key" ]; then echo "could not generate a key" >&2; exit 1; fi; \
		awk -v k="$$key" '/^APP_ENCRYPTION_KEY=/ {print "APP_ENCRYPTION_KEY=" k; next} {print}' \
			.env > .env.tmp && mv .env.tmp .env; \
		echo "Wrote a fresh APP_ENCRYPTION_KEY to .env"; \
	fi
	@echo "Ready. Run 'make up' then 'make cli'."

.env:
	@cp .env.example .env
	@echo "Created .env from .env.example"

.PHONY: genkey
genkey: ## Print a fresh APP_ENCRYPTION_KEY
	@$(COMPOSE) run --rm --no-deps -T cli genkey

.PHONY: build
build: ## Build the CLI image (runs the unit tests as part of the build)
	@VERSION=$(VERSION) $(COMPOSE) build cli

.PHONY: up
up: ## Start the database in the background
	@$(COMPOSE) up -d db
	@echo "Waiting for postgres to report healthy..."
	@$(COMPOSE) ps db

.PHONY: cli
cli: ## Open the interactive login shell
	@$(COMPOSE) run --rm cli

.PHONY: migrate
migrate: ## Apply database migrations without opening the shell
	@$(COMPOSE) run --rm --build migrate

.PHONY: logs
logs: ## Follow the database logs
	@$(COMPOSE) logs -f db

.PHONY: psql
psql: ## Open a psql prompt against the running database
	@$(COMPOSE) exec db psql -U $${POSTGRES_USER:-app} -d $${POSTGRES_DB:-clilogin}

.PHONY: down
down: ## Stop the containers, keeping the data volume
	@$(COMPOSE) down

.PHONY: clean
clean: ## Stop everything and delete the data volume (destroys all accounts)
	@$(COMPOSE) down -v --remove-orphans

.PHONY: restart-db
restart-db: ## Restart the database, proving data persists across restarts
	@$(COMPOSE) restart db
	@$(COMPOSE) ps db

# ------------------------------------------------------------------ local Go
# These need a local Go 1.23+ toolchain; the docker targets above do not.

.PHONY: deps
deps: ## Resolve dependencies and write go.sum
	go mod tidy

.PHONY: fmt
fmt: ## Format the source
	gofmt -s -w .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: test
test: ## Run the unit tests
	go test ./... -count=1

.PHONY: test-cover
test-cover: ## Run the tests with a coverage summary
	go test ./... -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

.PHONY: test-integration
test-integration: ## Run every test, including the ones needing a live database
	@$(COMPOSE) up -d db
	@$(COMPOSE) run --rm --build tests

.PHONY: test-integration-local
test-integration-local: ## Same, using a local Go toolchain and a published db port
	TEST_DATABASE_URL="postgres://$${POSTGRES_USER:-app}:$${POSTGRES_PASSWORD:-change_me_in_dotenv}@localhost:5432/$${POSTGRES_DB:-clilogin}?sslmode=disable" \
		go test ./... -count=1

.PHONY: check
check: fmt vet test ## Format, vet and test

.PHONY: build-local
build-local: ## Build the binary into bin/
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/cli-login ./cmd/cli-login
