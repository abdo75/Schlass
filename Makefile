.PHONY: setup build build-docker dev dev-frontend test test-unit test-integration audit-load e2e clean lint lint-fix audit-lint

setup:
	git config core.hooksPath .githooks
	cd web && npm ci
	@echo "Setup complete. Pre-commit hooks enabled."

build:
	cd web && npm ci && npm run build
	touch internal/web/dist/.gitkeep
	go build -o bin/schlass ./cmd/schlass

build-docker:
	docker build -t schlass .

dev:
	docker compose up --build

dev-frontend:
	cd web && npm run dev

test: test-unit test-integration

test-unit:
	go test ./internal/... -count=1

test-integration:
	go test -tags=integration ./test/integration/... -count=1 -timeout 5m

# REQ-AUD M10 Drill 1: sustained-rate load test against chain.Append.
# Knobs read from env: AUDIT_LOAD_RATE (default 200), AUDIT_LOAD_DURATION
# (default 5s), AUDIT_LOAD_WORKERS (default 8). For the spec-target 30-min
# drill: AUDIT_LOAD_DURATION=30m make audit-load.
audit-load:
	go test -tags='integration loadtest' -run TestAuditLoad_SustainedRate \
		-count=1 -timeout 45m -v ./test/integration/...

e2e:
	docker compose down -v
	SCHLASS_LOGIN_RATE_LIMIT=1000 docker compose -f docker-compose.yml -f docker-compose.e2e.yml up --build -d
	./scripts/wait-for-health.sh
	cd web && npx playwright test

clean:
	rm -rf bin/ internal/web/dist/*
	touch internal/web/dist/.gitkeep

lint: audit-lint
	golangci-lint run ./...
	cd web && npx eslint src/ --max-warnings=0

# REQ-AUD-011 (M2): static gate against denylisted metadata keys in
# audit.Event composite literals. Fails CI on violation.
audit-lint:
	go run ./tools/audit-lint ./internal/...

lint-fix:
	golangci-lint run ./... --fix
	cd web && npx eslint src/ --fix
