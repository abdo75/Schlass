import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { ClientSecretModal } from "@/components/ClientSecretModal";
import { createClient } from "./api";

const ALL_SCOPES = ["openid", "profile", "email", "offline_access"] as const;
const ALL_GRANTS = ["authorization_code", "refresh_token"] as const;

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: "Required for OIDC. Issues an ID token alongside the access token.",
  profile: "User's display name, preferred username, and locale.",
  email: "User's email address and verification status.",
  offline_access:
    "Required to issue refresh tokens. Enables long-lived sessions.",
};

const GRANT_DESCRIPTIONS: Record<string, string> = {
  authorization_code: "Standard browser-based OIDC flow with PKCE.",
  refresh_token: "Rotates on every use. Requires the offline_access scope.",
};

export function ClientCreatePage() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [redirects, setRedirects] = useState<string[]>([""]);
  const [scopes, setScopes] = useState<string[]>([...ALL_SCOPES]);
  const [grants, setGrants] = useState<string[]>([...ALL_GRANTS]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [revealed, setRevealed] = useState<{
    clientId: string;
    secret: string;
  } | null>(null);

  function toggle(
    list: string[],
    setList: (v: string[]) => void,
    item: string,
  ) {
    setList(
      list.includes(item) ? list.filter((s) => s !== item) : [...list, item],
    );
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await createClient({
        name,
        client_type: "confidential",
        redirect_uris: redirects.filter((r) => r.trim() !== ""),
        allowed_grant_types: grants,
        allowed_scopes: scopes,
      });
      setRevealed({ clientId: res.client_id, secret: res.client_secret });
    } catch (err: unknown) {
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setError(code);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <AdminPageHeader
        breadcrumbPath={[
          { label: "Clients", to: "/admin/clients" },
          { label: "New client" },
        ]}
      />
      <AdminPageContent>
        <form
          onSubmit={(e) => {
            void handleSubmit(e);
          }}
          className="mx-auto max-w-[680px]"
        >
          <div className="rounded-xl border border-border bg-background">
            {/* Section: Client type */}
            <section className="px-7 py-6">
              <div className="mb-3.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                Client type
              </div>
              <div className="flex flex-col gap-2">
                <label className="flex cursor-pointer gap-3 rounded-lg border-[1.5px] border-primary bg-primary/5 p-4">
                  <input
                    type="radio"
                    checked
                    readOnly
                    className="mt-0.5 accent-primary"
                  />
                  <div className="flex-1">
                    <div className="text-sm font-semibold text-foreground">
                      Confidential
                    </div>
                    <p className="mt-0.5 text-[13px] leading-snug text-muted-foreground">
                      Server-side application that can protect a secret.
                      Exchanges authorization codes at{" "}
                      <code className="font-mono">/token</code> using an
                      HTTP-sent client secret.
                    </p>
                  </div>
                </label>
                <label className="flex cursor-not-allowed gap-3 rounded-lg border border-border bg-muted/40 p-4 opacity-60">
                  <input type="radio" disabled className="mt-0.5" />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-foreground">
                        Public
                      </span>
                      <span className="inline-flex h-[18px] items-center rounded-full border border-border bg-muted px-[7px] text-[10px] font-medium text-muted-foreground">
                        Not yet available
                      </span>
                    </div>
                    <p className="mt-0.5 text-[13px] leading-snug text-muted-foreground">
                      Browser or mobile app that can&apos;t hold a secret.
                      PKCE-only authentication.
                    </p>
                  </div>
                </label>
              </div>
            </section>

            {/* Section: Name */}
            <section className="px-7 py-6">
              <label
                htmlFor="client-name"
                className="mb-2.5 block text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground"
              >
                Name
              </label>
              <input
                id="client-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={100}
                required
                placeholder="customer-portal"
                className="h-9 w-full rounded-lg border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-primary/40"
              />
              <p className="mt-2 text-[12px] text-muted-foreground">
                Internal label for this client. Not shown to users.
              </p>
            </section>

            {/* Section: Redirect URIs */}
            <section className="px-7 py-6">
              <div className="mb-2.5 flex items-baseline justify-between">
                <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                  Redirect URIs
                </span>
                <span className="text-[12px] text-muted-foreground/80">
                  {redirects.length} / 10
                </span>
              </div>
              <div className="flex flex-col gap-2">
                {redirects.map((uri, i) => (
                  <div key={i} className="flex gap-2">
                    <input
                      type="text"
                      value={uri}
                      onChange={(e) =>
                        setRedirects(
                          redirects.map((u, j) =>
                            j === i ? e.target.value : u,
                          ),
                        )
                      }
                      placeholder="https://..."
                      className="h-9 flex-1 rounded-lg border border-input bg-background px-3 font-mono text-[13px] outline-none focus:ring-2 focus:ring-primary/40"
                    />
                    {redirects.length > 1 && (
                      <button
                        type="button"
                        aria-label="Remove"
                        onClick={() =>
                          setRedirects(redirects.filter((_, j) => j !== i))
                        }
                        className="h-9 w-9 rounded-lg border border-input bg-background text-base text-muted-foreground hover:bg-muted/50"
                      >
                        ×
                      </button>
                    )}
                  </div>
                ))}
                {redirects.length < 10 && (
                  <button
                    type="button"
                    onClick={() => setRedirects([...redirects, ""])}
                    className="self-start text-[13px] font-medium text-primary hover:underline"
                  >
                    + Add redirect URI
                  </button>
                )}
              </div>
              <p className="mt-2.5 text-[12px] text-muted-foreground">
                Exact match at <code className="font-mono">/authorize</code>.
                HTTPS required, except loopback.
              </p>
            </section>

            {/* Section: Scopes */}
            <PermSection
              label="Scopes"
              items={ALL_SCOPES}
              selected={scopes}
              descriptions={SCOPE_DESCRIPTIONS}
              onToggle={(s) => toggle(scopes, setScopes, s)}
            />

            {/* Section: Grant types */}
            <PermSection
              label="Grant types"
              items={ALL_GRANTS}
              selected={grants}
              descriptions={GRANT_DESCRIPTIONS}
              onToggle={(g) => toggle(grants, setGrants, g)}
            />
          </div>

          {error && (
            <p className="mt-4 text-sm text-destructive" role="alert">
              {error}
            </p>
          )}

          <div className="mt-5 flex items-center justify-end gap-4 pl-1">
            <button
              type="button"
              onClick={() => {
                void navigate("/admin/clients");
              }}
              className="text-sm font-medium text-muted-foreground hover:text-foreground"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || name.trim() === ""}
              className="inline-flex h-9 items-center rounded-lg bg-primary px-5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {submitting ? "Creating…" : "Create"}
            </button>
          </div>
        </form>
      </AdminPageContent>

      {revealed && (
        <ClientSecretModal
          clientId={revealed.clientId}
          clientSecret={revealed.secret}
          onClose={() => {
            void navigate(`/admin/clients/${revealed.clientId}`);
          }}
        />
      )}
    </>
  );
}

function PermSection({
  label,
  items,
  selected,
  descriptions,
  onToggle,
}: {
  label: string;
  items: readonly string[];
  selected: string[];
  descriptions: Record<string, string>;
  onToggle: (s: string) => void;
}) {
  return (
    <section className="px-7 py-6">
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
        {label}
      </div>
      <div className="flex flex-col">
        {items.map((item) => (
          <label
            key={item}
            className="flex cursor-pointer items-start gap-3.5 py-2.5"
          >
            <input
              type="checkbox"
              checked={selected.includes(item)}
              onChange={() => onToggle(item)}
              className="mt-0.5 h-4 w-4 accent-primary"
            />
            <div className="flex-1">
              <div className="font-mono text-[13px] font-medium text-foreground">
                {item}
              </div>
              <div className="mt-0.5 text-[12px] text-muted-foreground">
                {descriptions[item]}
              </div>
            </div>
          </label>
        ))}
      </div>
    </section>
  );
}
