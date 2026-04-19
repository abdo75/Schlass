import { useCallback, useEffect, useState } from "react";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { CopyButton } from "@/components/ui/CopyButton";
import {
  listSigningKeys,
  rotateSigningKey,
  emergencyRetireSigningKey,
  type SigningKey,
} from "./api";
import { friendlyError } from "./errorDisplay";

// Retirement window matches backend RetireSweep cutoff: the grace period is
// access-token TTL (15m) + refresh-token TTL (24h) + clock skew (30s). After
// rotated_at + this window, the sweep moves the key from retiring → retired
// and drops it from the JWKS feed.
const RETIRE_WINDOW_MS = (24 * 60 + 15) * 60 * 1000 + 30 * 1000;

function absUTC(iso: string): string {
  const d = new Date(iso);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${y}-${m}-${day} ${hh}:${mm} UTC`;
}

function relative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function retirementCountdown(rotatedAt: string | null): string {
  if (!rotatedAt) return "retires soon";
  const remaining = new Date(rotatedAt).getTime() + RETIRE_WINDOW_MS - Date.now();
  if (remaining <= 0) return "fully retires shortly";
  const hrs = Math.floor(remaining / (60 * 60 * 1000));
  const mins = Math.floor((remaining % (60 * 60 * 1000)) / 60000);
  return `Fully retires in ${hrs}h ${mins}m`;
}

export function SigningKeysPage() {
  const [keys, setKeys] = useState<SigningKey[] | null>(null);
  const [rotating, setRotating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rotateOpen, setRotateOpen] = useState(false);
  const [retireTargetKid, setRetireTargetKid] = useState<string | null>(null);
  const [retiringNow, setRetiringNow] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await listSigningKeys();
      setKeys(res.keys);
    } catch (err: unknown) {
      setError(friendlyError(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleRotate() {
    setRotating(true);
    setError(null);
    try {
      await rotateSigningKey();
      await load();
    } catch (err: unknown) {
      setError(friendlyError(err));
    } finally {
      setRotating(false);
    }
  }

  async function handleEmergencyRetire(kid: string) {
    setRetiringNow(true);
    setError(null);
    try {
      await emergencyRetireSigningKey(kid);
      await load();
    } catch (err: unknown) {
      setError(friendlyError(err));
    } finally {
      setRetiringNow(false);
      setRetireTargetKid(null);
    }
  }

  const active = keys?.find((k) => k.status === "active") ?? null;
  const retiring = keys?.filter((k) => k.status === "retiring") ?? [];

  return (
    <>
      <AdminPageHeader
        title="Signing keys"
        subtitle="RS256 keypairs used to sign ID tokens and access tokens."
        primaryAction={
          <button
            type="button"
            onClick={() => setRotateOpen(true)}
            disabled={rotating || keys === null}
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

        {keys === null ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : (
          <div className="mx-auto max-w-[760px]">
            {/* Active key card — featured key id, top accent strip,
                status dot + label, bottom metadata strip. */}
            {active && (
              <div className="mb-3 overflow-hidden rounded-xl border border-border bg-background">
                <div className="h-[3px] bg-gradient-to-r from-primary to-primary/60" />
                <div className="px-7 pb-[22px] pt-5">
                  <div className="mb-3.5 flex items-center justify-between">
                    <span className="inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                      <span className="relative flex size-[7px]">
                        <span className="absolute inset-0 rounded-full bg-primary opacity-25 ring-4 ring-primary/15" />
                        <span className="relative inline-block size-[7px] rounded-full bg-primary" />
                      </span>
                      Active key
                    </span>
                    <span className="text-[12px] text-muted-foreground">
                      Signs all new tokens
                    </span>
                  </div>

                  {/* Featured key id */}
                  <div className="mb-4 flex items-center gap-2.5">
                    <code className="min-w-0 flex-1 break-all rounded-[10px] border border-border bg-muted px-3.5 py-2.5 font-mono text-[13px] tracking-[-0.01em] text-foreground">
                      {active.kid}
                    </code>
                    <CopyButton value={active.kid} label="key ID" size="md" />
                  </div>

                  {/* Metadata strip */}
                  <div className="flex gap-7 border-t border-border/60 pt-3.5 text-[13px]">
                    <div>
                      <div className="mb-0.5 text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                        Algorithm
                      </div>
                      <div className="font-mono text-foreground">
                        {active.algorithm}
                      </div>
                    </div>
                    <div>
                      <div className="mb-0.5 text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                        Generated
                      </div>
                      <div className="text-foreground">
                        {relative(active.created_at)}{" "}
                        <span className="text-muted-foreground/80">
                          · {absUTC(active.created_at)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Retiring keys card — absent when empty */}
            {retiring.length > 0 && (
              <div className="mb-3 rounded-xl border border-border bg-background px-7 py-6">
                <div className="mb-3.5 flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                    Retiring keys
                  </span>
                  <span className="text-[12px] text-muted-foreground">
                    Validates outstanding tokens only
                  </span>
                </div>

                <div className="flex flex-col gap-2.5">
                  {retiring.map((k) => (
                    <div
                      key={k.kid}
                      className="flex items-center justify-between gap-3 rounded-lg border border-warning-border bg-warning/30 px-3.5 py-3"
                    >
                      <div className="flex min-w-0 items-center gap-3">
                        <span className="inline-flex h-5 items-center rounded-full bg-warning/70 px-2 text-[11px] font-medium text-warning-foreground">
                          retiring
                        </span>
                        <code className="truncate font-mono text-[13px] text-foreground">
                          {k.kid}
                        </code>
                      </div>
                      <div className="flex shrink-0 items-center gap-3">
                        <span className="text-[12px] text-muted-foreground">
                          {retirementCountdown(k.rotated_at)}
                        </span>
                        <button
                          type="button"
                          onClick={() => setRetireTargetKid(k.kid)}
                          disabled={retiringNow}
                          className="inline-flex h-7 items-center rounded-md border border-destructive/40 bg-transparent px-2.5 text-[12px] font-medium text-destructive hover:bg-destructive/10 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          Retire now
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Lifecycle explainer */}
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
                  After the grace period, the retiring key is removed from the
                  JWKS feed and marked retired.
                </li>
                <li>
                  Private keys are AES-256-GCM encrypted at rest using{" "}
                  <code className="font-mono">SCHLASS_ENCRYPTION_KEY</code>.
                </li>
              </ul>
            </div>
          </div>
        )}
      </AdminPageContent>

      <ConfirmDialog
        open={rotateOpen}
        onOpenChange={setRotateOpen}
        variant="primary"
        title="Rotate the signing key?"
        body="A fresh RS256 keypair is generated and marked active. The current key becomes retiring and keeps validating outstanding tokens for 24 hours + 15 minutes before the retire sweep drops it from JWKS."
        confirmLabel="Rotate key"
        onConfirm={() => void handleRotate()}
      />

      <ConfirmDialog
        open={retireTargetKid !== null}
        onOpenChange={(open) => {
          if (!open) setRetireTargetKid(null);
        }}
        variant="destructive"
        title="Retire this key immediately?"
        body="Removes this key from JWKS immediately. Outstanding access and ID tokens signed by it will fail validation on their next use. Use only for suspected key compromise."
        confirmLabel="Retire now"
        onConfirm={() => {
          if (retireTargetKid) void handleEmergencyRetire(retireTargetKid);
        }}
      />
    </>
  );
}
