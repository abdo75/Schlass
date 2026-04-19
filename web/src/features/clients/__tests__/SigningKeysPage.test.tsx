import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { SigningKeysPage } from "../SigningKeysPage";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("@/lib/api", () => ({
  apiFetch: vi.fn(),
  // friendlyError() references ApiRequestError via instanceof, so the mock
  // has to expose the real class (or a stand-in). Re-exporting a minimal
  // class preserves the error-mapping behavior under test without pulling
  // the whole real module in.
  ApiRequestError: class ApiRequestError extends Error {
    code = "MOCK";
    status = 0;
  },
}));
vi.mock("@/features/auth/api");

import { apiFetch } from "@/lib/api";

// /.well-known/jwks.json is fetched directly via fetch() (not apiFetch) —
// stub it globally so SigningKeysPage's initial load has a deterministic
// response. Tests that need a specific key set override this.
function mockJWKS(keys: { kid: string; alg: string }[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          keys: keys.map((k) => ({
            kid: k.kid,
            kty: "RSA",
            alg: k.alg,
            use: "sig",
            n: "n",
            e: "AQAB",
          })),
        }),
    }),
  );
}

function wrap() {
  return (
    <MemoryRouter>
      <AuthProvider>
        <SigningKeysPage />
      </AuthProvider>
    </MemoryRouter>
  );
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
    // Mock window.confirm to auto-accept
    vi.stubGlobal("confirm", vi.fn().mockReturnValue(true));
    // Default JWKS response — single active key.
    mockJWKS([{ kid: "kid-0", alg: "RS256" }]);
  });

  it("renders the Rotate key button", () => {
    render(wrap());
    expect(
      screen.getByRole("button", { name: "Rotate key" }),
    ).toBeInTheDocument();
  });

  it("renders the lifecycle explainer card", () => {
    render(wrap());
    expect(screen.getByText("How rotation works")).toBeInTheDocument();
    // "retiring" appears in multiple <li> items — check for text within any list item
    const listItems = screen.getAllByRole("listitem");
    const hasRetiring = listItems.some((li) =>
      li.textContent?.includes("retiring"),
    );
    expect(hasRetiring).toBe(true);
    expect(screen.getByText("SCHLASS_ENCRYPTION_KEY")).toBeInTheDocument();
  });

  it("calls the rotate API and shows success banner on confirm", async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce(undefined);

    render(wrap());

    fireEvent.click(screen.getByRole("button", { name: "Rotate key" }));

    await waitFor(() =>
      expect(
        screen.getByText(/Signing key rotated/),
      ).toBeInTheDocument(),
    );

    expect(apiFetch).toHaveBeenCalledWith(
      "/api/admin/signing-keys/rotate",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("does not call the rotate API when confirm is cancelled", async () => {
    vi.stubGlobal("confirm", vi.fn().mockReturnValue(false));

    render(wrap());

    fireEvent.click(screen.getByRole("button", { name: "Rotate key" }));

    // Give any promises a chance to resolve
    await waitFor(() =>
      expect(apiFetch).not.toHaveBeenCalled(),
    );
  });

  it("renders the active key from JWKS", async () => {
    mockJWKS([{ kid: "first-active-kid", alg: "RS256" }]);
    render(wrap());
    await waitFor(() =>
      expect(screen.getByText("first-active-kid")).toBeInTheDocument(),
    );
    expect(screen.getByText("Active")).toBeInTheDocument();
  });

  it("labels the second key as Retiring when JWKS has multiple", async () => {
    mockJWKS([
      { kid: "new-active-kid", alg: "RS256" },
      { kid: "old-retiring-kid", alg: "RS256" },
    ]);
    render(wrap());
    await waitFor(() =>
      expect(screen.getByText("new-active-kid")).toBeInTheDocument(),
    );
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Retiring")).toBeInTheDocument();
    expect(screen.getByText("old-retiring-kid")).toBeInTheDocument();
  });
});
