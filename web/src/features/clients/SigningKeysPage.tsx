import { useState } from "react";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { rotateSigningKey } from "./api";

export function SigningKeysPage() {
  const [rotating, setRotating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [justRotated, setJustRotated] = useState(false);

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
    } catch (err: unknown) {
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setError(code);
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
