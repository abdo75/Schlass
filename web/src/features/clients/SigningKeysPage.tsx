import { useCallback, useEffect, useState } from "react";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { CopyButton } from "@/components/ui/CopyButton";
import { getJWKS, rotateSigningKey, type JWK } from "./api";
import { friendlyError } from "./errorDisplay";

type KeyRow = JWK & { label: "Active" | "Retiring" };

function toRows(jwks: { keys: JWK[] }): KeyRow[] {
  // Server orders the JWKS active-first then retiring (see
  // ListPublishable in internal/store/signing_key_store.go). Index 0 is
  // always the current signing key when any keys exist.
  return jwks.keys.map((k, i) => ({
    ...k,
    label: i === 0 ? "Active" : "Retiring",
  }));
}

export function SigningKeysPage() {
  const [rows, setRows] = useState<KeyRow[] | null>(null);
  const [rotating, setRotating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [justRotated, setJustRotated] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const jwks = await getJWKS();
      setRows(toRows(jwks));
    } catch (err: unknown) {
      setError(friendlyError(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleRotate() {
    if (
      !window.confirm(
        "Rotate the signing key now? The current key will remain valid for outstanding tokens for 24 hours.",
      )
    )
      return;
    setRotating(true);
    setError(null);
    try {
      await rotateSigningKey();
      setJustRotated(true);
      await load();
    } catch (err: unknown) {
      setError(friendlyError(err));
    } finally {
      setRotating(false);
    }
  }

  return (
    <>
      <AdminPageHeader
        title="Signing keys"
        subtitle="RS256 keypairs used to sign ID tokens and access tokens."
        primaryAction={
          <button
            type="button"
            onClick={() => void handleRotate()}
            disabled={rotating}
            className="inline-flex h-8 items-center rounded-lg bg-primary px-3.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {rotating ? "Rotating…" : "Rotate key"}
          </button>
        }
      />
      <AdminPageContent>
        {error && (
          <p className="mb-4 text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        {justRotated && (
          <div className="mb-4 rounded-lg border border-primary/30 bg-primary/5 px-4 py-3 text-sm text-foreground">
            Signing key rotated. The previous active key is now retiring and
            will continue validating outstanding tokens for 24 hours + 15
            minutes.
          </div>
        )}

        {/* Key list */}
        <div className="mb-4 overflow-hidden rounded-xl border border-border bg-background">
          <div className="grid grid-cols-[1fr_110px_90px_60px] gap-3 border-b border-border bg-sidebar px-6 py-3">
            <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
              Key ID
            </span>
            <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
              Status
            </span>
            <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
              Algorithm
            </span>
            <span />
          </div>
          {rows === null ? (
            <div className="px-6 py-8 text-center text-sm text-muted-foreground">
              Loading…
            </div>
          ) : rows.length === 0 ? (
            <div className="px-6 py-8 text-center text-sm text-muted-foreground">
              No signing keys published. This should not happen — the server
              bootstrap inserts an active key on first startup.
            </div>
          ) : (
            rows.map((row) => (
              <div
                key={row.kid}
                className="grid grid-cols-[1fr_110px_90px_60px] items-center gap-3 border-b border-border px-6 py-4 last:border-b-0"
              >
                <code className="truncate font-mono text-[13px] text-foreground">
                  {row.kid}
                </code>
                <span
                  className={
                    row.label === "Active"
                      ? "inline-flex h-6 items-center rounded-full bg-primary/10 px-2.5 text-[11px] font-medium uppercase tracking-wider text-primary"
                      : "inline-flex h-6 items-center rounded-full bg-warning/20 px-2.5 text-[11px] font-medium uppercase tracking-wider text-warning-foreground"
                  }
                >
                  {row.label}
                </span>
                <span className="font-mono text-[12px] text-muted-foreground">
                  {row.alg}
                </span>
                <CopyButton value={row.kid} label="key ID" />
              </div>
            ))
          )}
        </div>

        {/* Explainer */}
        <div className="rounded-xl border border-border bg-background px-7 py-5">
          <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
            How rotation works
          </div>
          <ul className="list-disc space-y-2 pl-5 text-[13px] leading-relaxed text-muted-foreground">
            <li>
              Clicking <strong>Rotate key</strong> generates a fresh RS256
              keypair and marks it active.
            </li>
            <li>
              The previous active key becomes <em>retiring</em> and keeps
              validating outstanding tokens for 24 hours + 15 minutes.
            </li>
            <li>
              After the grace period, the retiring key is removed from the JWKS
              feed and marked retired.
            </li>
            <li>
              Private keys are AES-256-GCM encrypted at rest using{" "}
              <code className="font-mono">SCHLASS_ENCRYPTION_KEY</code>.
            </li>
          </ul>
        </div>
      </AdminPageContent>
    </>
  );
}
