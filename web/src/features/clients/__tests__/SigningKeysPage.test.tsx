import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { SigningKeysPage } from "../SigningKeysPage";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("@/lib/api", () => ({
  apiFetch: vi.fn(),
  ApiRequestError: class ApiRequestError extends Error {
    code = "MOCK";
    status = 0;
  },
}));
vi.mock("@/features/auth/api");

import { apiFetch } from "@/lib/api";

function wrap() {
  return (
    <MemoryRouter>
      <AuthProvider>
        <SigningKeysPage />
      </AuthProvider>
    </MemoryRouter>
  );
}

function setKeys(
  rows: { kid: string; status: "active" | "retiring"; rotated_at?: string | null }[],
) {
  const now = new Date().toISOString();
  const payload = {
    keys: rows.map((r) => ({
      kid: r.kid,
      algorithm: "RS256",
      status: r.status,
      created_at: now,
      rotated_at: r.rotated_at ?? null,
    })),
  };
  (apiFetch as ReturnType<typeof vi.fn>).mockImplementation(((
    path: string,
  ): Promise<unknown> =>
    path === "/api/admin/signing-keys"
      ? Promise.resolve(payload)
      : Promise.resolve(undefined)) as (...args: unknown[]) => unknown);
}

describe("SigningKeysPage", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: {
        id: "u-0",
        email: "admin@example.com",
        role: "super_admin",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
    vi.stubGlobal("confirm", vi.fn().mockReturnValue(true));
    setKeys([{ kid: "kid-active", status: "active" }]);
  });

  it("renders the Active key card with kid + algorithm + generated timestamp", async () => {
    render(wrap());
    await waitFor(() =>
      expect(screen.getByText("kid-active")).toBeInTheDocument(),
    );
    expect(screen.getByText("Active key")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.getByText("RS256")).toBeInTheDocument();
  });

  it("omits the Retiring card when there are no retiring keys", async () => {
    render(wrap());
    await waitFor(() =>
      expect(screen.getByText("kid-active")).toBeInTheDocument(),
    );
    expect(screen.queryByText("Retiring keys")).not.toBeInTheDocument();
  });

  it("renders a Retiring card with countdown when retiring keys exist", async () => {
    const rotatedAt = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    setKeys([
      { kid: "kid-new-active", status: "active" },
      { kid: "kid-retiring", status: "retiring", rotated_at: rotatedAt },
    ]);
    render(wrap());
    await waitFor(() =>
      expect(screen.getByText("kid-retiring")).toBeInTheDocument(),
    );
    expect(screen.getByText("Retiring keys")).toBeInTheDocument();
    // "retiring" also appears in the lifecycle explainer prose, so match the
    // badge specifically by looking inside the card near the kid row.
    const retiringRow = screen.getByText("kid-retiring").parentElement;
    expect(retiringRow?.textContent).toContain("retiring");
    expect(screen.getByText(/Fully retires in/)).toBeInTheDocument();
  });

  it("renders the lifecycle explainer card", async () => {
    render(wrap());
    await waitFor(() => expect(screen.getByText("kid-active")).toBeInTheDocument());
    expect(screen.getByText("How rotation works")).toBeInTheDocument();
    expect(screen.getByText("SCHLASS_ENCRYPTION_KEY")).toBeInTheDocument();
  });

  it("calls the rotate API after the confirm dialog's Rotate key action", async () => {
    render(wrap());
    await waitFor(() => expect(screen.getByText("kid-active")).toBeInTheDocument());
    // First click opens the styled ConfirmDialog.
    fireEvent.click(screen.getByRole("button", { name: "Rotate key" }));
    // The dialog's primary button shares the label — click the last match.
    const buttons = screen.getAllByRole("button", { name: "Rotate key" });
    fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() =>
      expect(apiFetch).toHaveBeenCalledWith(
        "/api/admin/signing-keys/rotate",
        expect.objectContaining({ method: "POST" }),
      ),
    );
  });

  it("does not call the rotate API when the dialog is cancelled", async () => {
    render(wrap());
    await waitFor(() => expect(screen.getByText("kid-active")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Rotate key" }));
    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));
    await waitFor(() => {
      const rotateCalls = (apiFetch as ReturnType<typeof vi.fn>).mock.calls.filter(
        (c) => c[0] === "/api/admin/signing-keys/rotate",
      );
      expect(rotateCalls).toHaveLength(0);
    });
  });
});
