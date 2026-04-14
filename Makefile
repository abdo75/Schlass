.PHONY: build build-docker dev dev-frontend test test-unit test-integration clean

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

test: internal/web/dist/.gitkeep
	go test ./...

test-unit: internal/web/dist/.gitkeep
	go test ./internal/...

test-integration: internal/web/dist/.gitkeep
	go test ./test/integration/...

clean:
	rm -rf bin/ internal/web/dist/*
	touch internal/web/dist/.gitkeep
