.PHONY: setup build build-docker dev dev-frontend test test-unit test-integration e2e clean lint lint-fix

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

e2e:
	docker compose down -v
	SCHLASS_LOGIN_RATE_LIMIT=1000 docker compose -f docker-compose.yml -f docker-compose.e2e.yml up --build -d
	./scripts/wait-for-health.sh
	cd web && npx playwright test

clean:
	rm -rf bin/ internal/web/dist/*
	touch internal/web/dist/.gitkeep

lint:
	golangci-lint run ./...
	cd web && npx eslint src/ --max-warnings=0

lint-fix:
	golangci-lint run ./... --fix
	cd web && npx eslint src/ --fix
