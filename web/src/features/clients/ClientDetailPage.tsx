import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { CopyButton } from "@/components/ui/CopyButton";
import { ClientSecretModal } from "@/components/ClientSecretModal";
import {
  getClient,
  updateClient,
  disableClient,
  enableClient,
  rotateClientSecret,
  deleteClient,
  type ClientDTO,
} from "./api";
import {
  ALL_SCOPES,
  ALL_GRANTS,
  SCOPE_DESCRIPTIONS,
  GRANT_DESCRIPTIONS,
  relativeTime,
} from "./constants";
import { friendlyError } from "./errorDisplay";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Section = "name" | "redirects" | "scopes" | "grants" | null;

// ---------------------------------------------------------------------------
// Main page component
// ---------------------------------------------------------------------------

export function ClientDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [client, setClient] = useState<ClientDTO | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<Section>(null);
  const [revealed, setRevealed] = useState<{
    clientId: string;
    secret: string;
  } | null>(null);
  const [deleteModal, setDeleteModal] = useState(false);
  const [disableOpen, setDisableOpen] = useState(false);
  const [enableOpen, setEnableOpen] = useState(false);
  const [rotateSecretOpen, setRotateSecretOpen] = useState(false);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const res = await getClient(id);
      setClient(res.client);
    } catch (err: unknown) {
      setError(friendlyError(err));
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleSaveSection(
    patch: Record<string, unknown>,
  ) {
    if (!id) return;
    try {
      const res = await updateClient(id, patch);
      setClient(res.client);
      setEditing(null);
    } catch (err: unknown) {
      setError(friendlyError(err));
    }
  }

  async function handleDisable() {
    if (!id || !client) return;
    try {
      await disableClient(id);
      await load();
    } catch (err: unknown) {
      setError(friendlyError(err));
    }
  }

  async function handleEnable() {
    if (!id) return;
    try {
      await enableClient(id);
      await load();
    } catch (err: unknown) {
      setError(friendlyError(err));
    }
  }

  async function handleRotate() {
    if (!id) return;
    try {
      const res = await rotateClientSecret(id);
      setRevealed({ clientId: res.client_id, secret: res.client_secret });
      await load();
    } catch (err: unknown) {
      setError(friendlyError(err));
    }
  }

  async function handleDelete() {
    if (!id) return;
    try {
      await deleteClient(id);
      void navigate("/admin/clients");
    } catch (err: unknown) {
      setError(friendlyError(err));
      setDeleteModal(false);
    }
  }

  return (
    <>
      <AdminPageHeader
        breadcrumbPath={[
          { label: "Clients", to: "/admin/clients" },
          { label: client?.name ?? id ?? "…" },
        ]}
      />
      <AdminPageContent>
        {loading && !client ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : error && !client ? (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        ) : client ? (
          <div className="mx-auto max-w-[760px]">
            {/* Header strip */}
            <div className="mb-6 flex items-center gap-4">
              <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-primary text-xl font-bold text-primary-foreground">
                {client.name[0]?.toUpperCase() ?? "?"}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5">
                  <h1 className="text-[20px] font-semibold leading-tight text-foreground">
                    {client.name}
                  </h1>
                  <StatusBadge status={client.status} />
                </div>
                <p className="mt-0.5 text-[13px] text-muted-foreground">
                  Created {relativeTime(client.created_at)}
                  {client.created_by_user_id
                    ? ` by ${client.created_by_user_id}`
                    : ""}
                </p>
              </div>
            </div>

            {error && (
              <p
                className="mb-4 text-sm text-destructive"
                role="alert"
              >
                {error}
              </p>
            )}

            {/* Main card */}
            <div className="rounded-xl border border-border bg-background">
              <IdentitySection
                key={editing === "name" ? "name-edit" : "name-view"}
                client={client}
                editing={editing === "name"}
                onEdit={() => setEditing("name")}
                onCancel={() => setEditing(null)}
                onSave={(newName) =>
                  void handleSaveSection({ name: newName })
                }
              />

              <RedirectsSection
                key={editing === "redirects" ? "redirects-edit" : "redirects-view"}
                client={client}
                editing={editing === "redirects"}
                onEdit={() => setEditing("redirects")}
                onCancel={() => setEditing(null)}
                onSave={(uris) =>
                  void handleSaveSection({ redirect_uris: uris })
                }
              />

              <ScopesSection
                key={editing === "scopes" ? "scopes-edit" : "scopes-view"}
                client={client}
                editing={editing === "scopes"}
                onEdit={() => setEditing("scopes")}
                onCancel={() => setEditing(null)}
                onSave={(scopes) =>
                  void handleSaveSection({ allowed_scopes: scopes })
                }
              />

              <GrantsSection
                key={editing === "grants" ? "grants-edit" : "grants-view"}
                client={client}
                editing={editing === "grants"}
                onEdit={() => setEditing("grants")}
                onCancel={() => setEditing(null)}
                onSave={(grants) =>
                  void handleSaveSection({ allowed_grant_types: grants })
                }
              />

              {/* Client secret section */}
              <section className="px-7 py-6">
                <div className="mb-3.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                  Client secret
                </div>
                <div className="flex items-center justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm text-foreground">
                      Last rotated {relativeTime(client.updated_at)}
                    </div>
                    <div className="mt-0.5 text-[12px] text-muted-foreground">
                      A 24-hour overlap window applies after rotation. The
                      previous secret keeps working until the window closes.
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setRotateSecretOpen(true)}
                    className="inline-flex h-8 items-center rounded-lg border border-input bg-background px-3.5 text-[13px] font-medium text-foreground hover:bg-muted/50"
                  >
                    Rotate secret
                  </button>
                </div>
              </section>
            </div>

            {/* Danger zone */}
            <div className="mt-4 rounded-xl border border-destructive/40 bg-background">
              {/* Disable / Enable */}
              <section className="px-7 py-5">
                <div className="flex items-center justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-foreground">
                      {client.status === "active"
                        ? "Disable client"
                        : "Enable client"}
                    </div>
                    <div className="mt-0.5 text-[13px] text-muted-foreground">
                      {client.status === "active"
                        ? "Blocks new authorizations and refresh grants. Outstanding access tokens expire naturally within 15 minutes. Reversible."
                        : "Re-enables the client with its existing secret. Rotate the secret now if the original disable was due to a suspected compromise."}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={
                      client.status === "active"
                        ? () => setDisableOpen(true)
                        : () => setEnableOpen(true)
                    }
                    className="inline-flex h-8 items-center rounded-lg border border-destructive bg-background px-3.5 text-[13px] font-medium text-destructive hover:bg-destructive/5"
                  >
                    {client.status === "active" ? "Disable" : "Enable"}
                  </button>
                </div>
              </section>

              {/* Delete */}
              <section className="px-7 py-5">
                <div className="flex items-center justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-foreground">
                      Delete client
                    </div>
                    <div className="mt-0.5 text-[13px] text-muted-foreground">
                      Permanent. Revokes all outstanding access tokens, deletes
                      pending authorization codes, and prevents the client ID
                      from ever authenticating again. Audit trail is preserved.
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setDeleteModal(true)}
                    className="inline-flex h-8 items-center rounded-lg bg-destructive px-3.5 text-[13px] font-medium text-destructive-foreground hover:bg-destructive/90"
                  >
                    Delete
                  </button>
                </div>
              </section>
            </div>
          </div>
        ) : null}
      </AdminPageContent>

      {revealed && (
        <ClientSecretModal
          clientId={revealed.clientId}
          clientSecret={revealed.secret}
          onClose={() => setRevealed(null)}
        />
      )}

      {deleteModal && client && (
        <DeleteConfirmModal
          clientName={client.name}
          onCancel={() => setDeleteModal(false)}
          onConfirm={() => void handleDelete()}
        />
      )}

      <ConfirmDialog
        open={disableOpen}
        onOpenChange={setDisableOpen}
        title="Disable this client?"
        body="Blocks new authorizations and refresh-token exchanges. Outstanding access tokens stay valid for up to 15 minutes until they expire. Reversible."
        confirmLabel="Disable client"
        onConfirm={() => void handleDisable()}
      />

      <ConfirmDialog
        open={enableOpen}
        onOpenChange={setEnableOpen}
        variant="primary"
        title="Re-enable this client?"
        body="Restores the client with its existing secret. If the disable was due to a suspected compromise, rotate the secret right after re-enabling."
        confirmLabel="Enable client"
        onConfirm={() => void handleEnable()}
      />

      <ConfirmDialog
        open={rotateSecretOpen}
        onOpenChange={setRotateSecretOpen}
        variant="primary"
        title="Rotate the client secret?"
        body="A new 32-byte secret is generated and shown once. The current secret keeps working for a 24-hour overlap window before it expires — your application can stay online while you roll the new credential."
        confirmLabel="Rotate secret"
        onConfirm={() => void handleRotate()}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Identity section
// ---------------------------------------------------------------------------

function IdentitySection({
  client,
  editing,
  onEdit,
  onCancel,
  onSave,
}: {
  client: ClientDTO;
  editing: boolean;
  onEdit: () => void;
  onCancel: () => void;
  onSave: (name: string) => void;
}) {
  // Draft is initialized from props; the parent provides a `key` that remounts
  // this component when toggling between view/edit mode, so the draft is always
  // fresh from props when entering edit mode.
  const [draft, setDraft] = useState(client.name);

  return (
    <section className="px-7 py-6">
      <div className="mb-3.5 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
          Identity
        </span>
        {!editing && (
          <button
            type="button"
            onClick={onEdit}
            className="text-[13px] font-medium text-primary hover:underline"
          >
            Edit
          </button>
        )}
      </div>

      {editing ? (
        <div className="flex flex-col gap-4">
          <div>
            <label
              htmlFor="client-name-edit"
              className="mb-1.5 block text-[12px] font-medium text-muted-foreground"
            >
              Name
            </label>
            <input
              id="client-name-edit"
              type="text"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              maxLength={100}
              autoFocus
              className="h-9 w-full rounded-lg border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-primary/40"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="h-8 rounded-lg border border-input bg-background px-3.5 text-[13px] font-medium text-muted-foreground hover:bg-muted/50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => onSave(draft.trim())}
              disabled={draft.trim().length === 0}
              className="h-8 rounded-lg bg-primary px-4 text-[13px] font-medium text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Save
            </button>
          </div>
        </div>
      ) : (
        <dl
          className="grid gap-x-6 gap-y-4 text-sm"
          style={{ gridTemplateColumns: "140px 1fr" }}
        >
          <dt className="text-[13px] text-muted-foreground">Name</dt>
          <dd className="font-medium">{client.name}</dd>

          <dt className="text-[13px] text-muted-foreground">Type</dt>
          <dd className="capitalize">{client.client_type}</dd>

          <dt className="text-[13px] text-muted-foreground">Client ID</dt>
          <dd className="flex items-center gap-2 min-w-0">
            <code className="truncate font-mono text-[13px]">{client.id}</code>
            <CopyButton value={client.id} label="client ID" />
          </dd>
        </dl>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Redirect URIs section
// ---------------------------------------------------------------------------

function RedirectsSection({
  client,
  editing,
  onEdit,
  onCancel,
  onSave,
}: {
  client: ClientDTO;
  editing: boolean;
  onEdit: () => void;
  onCancel: () => void;
  onSave: (uris: string[]) => void;
}) {
  const [draft, setDraft] = useState<string[]>(client.redirect_uris);

  return (
    <section className="px-7 py-6">
      <div className="mb-3.5 flex items-center justify-between">
        <div className="flex items-baseline gap-3">
          <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
            Redirect URIs
          </span>
          {!editing && (
            <span className="text-[12px] text-muted-foreground/70">
              {client.redirect_uris.length} / 10
            </span>
          )}
        </div>
        {!editing && (
          <button
            type="button"
            onClick={onEdit}
            className="text-[13px] font-medium text-primary hover:underline"
          >
            Edit
          </button>
        )}
      </div>

      {editing ? (
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            {draft.map((uri, i) => (
              <div key={i} className="flex gap-2">
                <input
                  type="text"
                  value={uri}
                  onChange={(e) =>
                    setDraft(draft.map((u, j) => (j === i ? e.target.value : u)))
                  }
                  placeholder="https://..."
                  className="h-9 flex-1 rounded-lg border border-input bg-background px-3 font-mono text-[13px] outline-none focus:ring-2 focus:ring-primary/40"
                />
                {draft.length > 1 && (
                  <button
                    type="button"
                    aria-label="Remove"
                    onClick={() => setDraft(draft.filter((_, j) => j !== i))}
                    className="h-9 w-9 rounded-lg border border-input bg-background text-base text-muted-foreground hover:bg-muted/50"
                  >
                    ×
                  </button>
                )}
              </div>
            ))}
            {draft.length < 10 && (
              <button
                type="button"
                onClick={() => setDraft([...draft, ""])}
                className="self-start text-[13px] font-medium text-primary hover:underline"
              >
                + Add redirect URI
              </button>
            )}
          </div>
          <p className="text-[12px] text-muted-foreground">
            Where Schlass sends users back after sign-in. Must match the URL
            your application expects exactly — trailing slash, scheme, port,
            everything. Use <code className="font-mono">https://</code> in
            production; <code className="font-mono">http://localhost</code> is
            allowed for local development only.
          </p>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="h-8 rounded-lg border border-input bg-background px-3.5 text-[13px] font-medium text-muted-foreground hover:bg-muted/50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() =>
                onSave(draft.filter((u) => u.trim() !== ""))
              }
              className="h-8 rounded-lg bg-primary px-4 text-[13px] font-medium text-primary-foreground hover:bg-primary/90"
            >
              Save
            </button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          {client.redirect_uris.map((uri) => (
            <code
              key={uri}
              className="rounded-lg bg-muted px-2.5 py-1 text-[12px] font-mono text-foreground"
            >
              {uri}
            </code>
          ))}
          {client.redirect_uris.length === 0 && (
            <span className="text-[13px] text-muted-foreground italic">
              None
            </span>
          )}
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Scopes section
// ---------------------------------------------------------------------------

function ScopesSection({
  client,
  editing,
  onEdit,
  onCancel,
  onSave,
}: {
  client: ClientDTO;
  editing: boolean;
  onEdit: () => void;
  onCancel: () => void;
  onSave: (scopes: string[]) => void;
}) {
  const [draft, setDraft] = useState<string[]>(client.allowed_scopes);

  function toggle(item: string) {
    setDraft((prev) =>
      prev.includes(item) ? prev.filter((s) => s !== item) : [...prev, item],
    );
  }

  return (
    <section className="px-7 py-6">
      <div className="mb-3.5 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
          Scopes
        </span>
        {!editing && (
          <button
            type="button"
            onClick={onEdit}
            className="text-[13px] font-medium text-primary hover:underline"
          >
            Edit
          </button>
        )}
      </div>

      {editing ? (
        <div className="flex flex-col gap-4">
          <div className="flex flex-col">
            {ALL_SCOPES.map((scope) => (
              <label
                key={scope}
                className="flex cursor-pointer items-start gap-3.5 py-2.5"
              >
                <input
                  type="checkbox"
                  checked={draft.includes(scope)}
                  onChange={() => toggle(scope)}
                  className="mt-0.5 h-4 w-4 accent-primary"
                />
                <div className="flex-1">
                  <div className="font-mono text-[13px] font-medium text-foreground">
                    {scope}
                  </div>
                  <div className="mt-0.5 text-[12px] text-muted-foreground">
                    {SCOPE_DESCRIPTIONS[scope]}
                  </div>
                </div>
              </label>
            ))}
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="h-8 rounded-lg border border-input bg-background px-3.5 text-[13px] font-medium text-muted-foreground hover:bg-muted/50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => onSave(draft)}
              className="h-8 rounded-lg bg-primary px-4 text-[13px] font-medium text-primary-foreground hover:bg-primary/90"
            >
              Save
            </button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          {client.allowed_scopes.map((scope) => (
            <span
              key={scope}
              className="inline-flex items-center rounded-full border border-border bg-muted px-3 py-0.5 font-mono text-[12px] text-foreground"
            >
              {scope}
            </span>
          ))}
          {client.allowed_scopes.length === 0 && (
            <span className="text-[13px] text-muted-foreground italic">
              None
            </span>
          )}
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Grant types section
// ---------------------------------------------------------------------------

function GrantsSection({
  client,
  editing,
  onEdit,
  onCancel,
  onSave,
}: {
  client: ClientDTO;
  editing: boolean;
  onEdit: () => void;
  onCancel: () => void;
  onSave: (grants: string[]) => void;
}) {
  const [draft, setDraft] = useState<string[]>(client.allowed_grant_types);

  function toggle(item: string) {
    setDraft((prev) =>
      prev.includes(item) ? prev.filter((g) => g !== item) : [...prev, item],
    );
  }

  return (
    <section className="px-7 py-6">
      <div className="mb-3.5 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
          Grant types
        </span>
        {!editing && (
          <button
            type="button"
            onClick={onEdit}
            className="text-[13px] font-medium text-primary hover:underline"
          >
            Edit
          </button>
        )}
      </div>

      {editing ? (
        <div className="flex flex-col gap-4">
          <div className="flex flex-col">
            {ALL_GRANTS.map((grant) => (
              <label
                key={grant}
                className="flex cursor-pointer items-start gap-3.5 py-2.5"
              >
                <input
                  type="checkbox"
                  checked={draft.includes(grant)}
                  onChange={() => toggle(grant)}
                  className="mt-0.5 h-4 w-4 accent-primary"
                />
                <div className="flex-1">
                  <div className="font-mono text-[13px] font-medium text-foreground">
                    {grant}
                  </div>
                  <div className="mt-0.5 text-[12px] text-muted-foreground">
                    {GRANT_DESCRIPTIONS[grant]}
                  </div>
                </div>
              </label>
            ))}
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="h-8 rounded-lg border border-input bg-background px-3.5 text-[13px] font-medium text-muted-foreground hover:bg-muted/50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => onSave(draft)}
              className="h-8 rounded-lg bg-primary px-4 text-[13px] font-medium text-primary-foreground hover:bg-primary/90"
            >
              Save
            </button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          {client.allowed_grant_types.map((grant) => (
            <span
              key={grant}
              className="inline-flex items-center rounded-full border border-border bg-muted px-3 py-0.5 font-mono text-[12px] text-foreground"
            >
              {grant}
            </span>
          ))}
          {client.allowed_grant_types.length === 0 && (
            <span className="text-[13px] text-muted-foreground italic">
              None
            </span>
          )}
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Delete confirm modal
// ---------------------------------------------------------------------------

function DeleteConfirmModal({
  clientName,
  onCancel,
  onConfirm,
}: {
  clientName: string;
  onCancel: () => void;
  onConfirm: () => void | Promise<void>;
}) {
  const [typed, setTyped] = useState("");
  const enabled = typed === clientName;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4">
      <div className="w-full max-w-lg overflow-hidden rounded-xl bg-background shadow-2xl">
        <div className="px-6 pb-4 pt-6">
          <div className="mb-1.5 flex items-center gap-2.5">
            <div className="flex h-6 w-6 items-center justify-center rounded-md bg-destructive/15 text-[13px] font-bold text-destructive">
              !
            </div>
            <h2 className="text-base font-semibold">Delete {clientName}</h2>
          </div>
          <p className="text-[13px] leading-snug text-muted-foreground">
            All outstanding access tokens are revoked immediately. Pending
            authorization codes are invalidated. The client ID is freed and
            cannot be restored. Audit history for this client is kept.
          </p>
        </div>
        <div className="px-6 pb-5">
          <label className="mb-2 block text-[13px] text-foreground">
            Type{" "}
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono">
              {clientName}
            </code>{" "}
            to confirm:
          </label>
          <input
            type="text"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={clientName}
            autoFocus
            className="h-9 w-full rounded-lg border border-input bg-background px-3 font-mono text-sm outline-none focus:ring-2 focus:ring-destructive/40"
          />
        </div>
        <div className="flex justify-end gap-2 border-t border-border bg-muted/30 px-6 py-4">
          <button
            type="button"
            onClick={onCancel}
            className="h-9 rounded-lg border border-input bg-background px-4 text-sm font-medium text-muted-foreground hover:bg-muted/50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void onConfirm()}
            disabled={!enabled}
            className="h-9 rounded-lg bg-destructive px-5 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Delete permanently
          </button>
        </div>
      </div>
    </div>
  );
}


