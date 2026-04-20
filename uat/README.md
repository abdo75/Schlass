# UAT — third-party OIDC relying parties

Drop-in compose files for spinning up real open-source OIDC clients that
authenticate against Schlass. Used for manual UAT only; this whole
directory is gitignored.

## Grafana

```bash
cd uat/grafana
docker compose up -d
```

Open http://localhost:3001, click "Sign in with Schlass", complete
Schlass login + MFA. Grafana lands you on its home dashboard with the
user identity shown top-right.

Stop:

```bash
docker compose down
```

Client credentials are baked into `uat/grafana/docker-compose.yml`. If
you rotate the client secret in the Schlass UI, update the compose file
and `docker compose up -d` to pick up the change.
