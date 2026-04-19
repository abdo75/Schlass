// /oidc/dev-callback is the redirect URI registered by the dev-seed OIDC
// client. In production there is no such RP — third-party clients own their
// own callback servers. This page exists purely for local development so a
// human running through the authorize flow can see the `code` + `state`
// that came back from /authorize, and optionally trigger a /token exchange
// from the browser.
//
// The backend /token endpoint normally should not be called from a browser
// (client_secret is supposed to be server-held), but the dev-seed secret is
// a well-known value baked into docker-compose.e2e.yml, so there's no real
// secret to leak here. Only served when the SPA is loaded — has no effect
// on production deployments where no OIDC client has this redirect URI
// registered.

import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

const DEV_CLIENT_SECRET = "e2e-deterministic-secret-do-not-ship";
const DEV_REDIRECT_URI = "http://localhost:3000/oidc/dev-callback";

export function DevCallbackPage() {
  const [params] = useSearchParams();
  const code = params.get("code");
  const state = params.get("state");
  const errorParam = params.get("error");
  const errorDescription = params.get("error_description");
  const clientId = useMemo(() => localStorage.getItem("schlass_dev_client_id") ?? "", []);
  const [clientIdInput, setClientIdInput] = useState(clientId);
  const [verifier, setVerifier] = useState("");
  const [tokens, setTokens] = useState<Record<string, unknown> | null>(null);
  const [exchangeError, setExchangeError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function exchange() {
    if (!code || !clientIdInput || !verifier) return;
    setSubmitting(true);
    setExchangeError(null);
    setTokens(null);
    try {
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: DEV_REDIRECT_URI,
        client_id: clientIdInput,
        client_secret: DEV_CLIENT_SECRET,
        code_verifier: verifier,
      });
      const res = await fetch("/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      });
      const json = (await res.json()) as Record<string, unknown>;
      if (!res.ok) {
        setExchangeError(
          `${res.status}: ${JSON.stringify(json)}`,
        );
        return;
      }
      setTokens(json);
      localStorage.setItem("schlass_dev_client_id", clientIdInput);
    } catch (err) {
      setExchangeError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold">OIDC dev callback</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Development-only landing page for the dev-seed OIDC client. Displays
          the <code className="font-mono">code</code> and{" "}
          <code className="font-mono">state</code> returned by{" "}
          <code className="font-mono">/authorize</code> and lets you trigger a{" "}
          <code className="font-mono">/token</code> exchange from the browser.
        </p>
      </header>

      {errorParam && (
        <section className="mb-6 rounded-lg border border-destructive/40 bg-destructive/5 p-4">
          <div className="text-sm font-semibold text-destructive">
            Authorization error
          </div>
          <div className="mt-1 font-mono text-[13px]">
            {errorParam}
            {errorDescription && <>: {errorDescription}</>}
          </div>
        </section>
      )}

      <section className="mb-6 rounded-lg border border-border bg-background p-4">
        <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
          Authorization response
        </div>
        <dl className="mt-3 grid grid-cols-[100px_1fr] gap-x-4 gap-y-2 text-[13px]">
          <dt className="text-muted-foreground">code</dt>
          <dd>
            {code ? (
              <code className="break-all font-mono">{code}</code>
            ) : (
              <span className="text-muted-foreground">(none)</span>
            )}
          </dd>
          <dt className="text-muted-foreground">state</dt>
          <dd>
            {state ? (
              <code className="break-all font-mono">{state}</code>
            ) : (
              <span className="text-muted-foreground">(none)</span>
            )}
          </dd>
        </dl>
      </section>

      {code && (
        <section className="mb-6 rounded-lg border border-border bg-background p-4">
          <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
            Exchange for tokens
          </div>
          <div className="space-y-3">
            <div>
              <label className="mb-1.5 block text-[13px] font-medium">
                Client ID
              </label>
              <input
                value={clientIdInput}
                onChange={(e) => setClientIdInput(e.target.value)}
                className="h-9 w-full rounded-lg border border-input bg-background px-3 font-mono text-[13px] outline-none focus:ring-2 focus:ring-primary/40"
                placeholder="UUID of the OIDC client"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-[13px] font-medium">
                PKCE code_verifier
              </label>
              <input
                value={verifier}
                onChange={(e) => setVerifier(e.target.value)}
                className="h-9 w-full rounded-lg border border-input bg-background px-3 font-mono text-[13px] outline-none focus:ring-2 focus:ring-primary/40"
                placeholder="The verifier whose SHA256 is the challenge you sent to /authorize"
              />
            </div>
            <button
              type="button"
              onClick={() => void exchange()}
              disabled={submitting || !clientIdInput || !verifier}
              className="inline-flex h-9 items-center rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {submitting ? "Exchanging…" : "Exchange for tokens"}
            </button>
          </div>
        </section>
      )}

      {exchangeError && (
        <section className="mb-6 rounded-lg border border-destructive/40 bg-destructive/5 p-4 text-[13px] text-destructive">
          <div className="font-semibold">Token exchange failed</div>
          <pre className="mt-1 whitespace-pre-wrap break-all font-mono">
            {exchangeError}
          </pre>
        </section>
      )}

      {tokens && (
        <section className="rounded-lg border border-primary/30 bg-primary/5 p-4">
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
            Tokens
          </div>
          <pre className="overflow-auto whitespace-pre-wrap break-all font-mono text-[12px] leading-relaxed">
            {JSON.stringify(tokens, null, 2)}
          </pre>
        </section>
      )}
    </div>
  );
}
