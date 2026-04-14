# Schlass

A self-hosted, open-source identity provider for EU-regulated SMEs.

Built for organisations that need documented, auditable identity and access management to comply with DORA and NIS2 — without the cost and complexity of Okta, Entra ID, or Keycloak.

## Quick Start

```bash
# Clone and setup
git clone https://github.com/abdo75/Schlass.git
cd Schlass
make setup

# Start locally
cp .env.example .env
# Generate a real encryption key:
# openssl rand -base64 32
# Replace the SCHLASS_ENCRYPTION_KEY value in .env

make dev
```

Open `http://localhost:3000/setup` and create your admin account.

## Development

```bash
make setup          # Install dependencies + configure git hooks
make dev            # Start all services (app + PG + Valkey)
make dev-frontend   # Vite HMR for frontend work
make test           # Run all tests (unit + integration)
make lint           # Run Go + frontend linters
make build          # Build production binary
```

## Stack

- **Backend:** Go, stdlib `net/http`, PostgreSQL, Valkey
- **Frontend:** React, TypeScript, Vite, Tailwind CSS, shadcn/ui
- **Deployment:** Single binary with embedded SPA

## License

[AGPL-3.0](LICENSE)
