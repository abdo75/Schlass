import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { SigningKeysPage } from "../SigningKeysPage";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("@/lib/api", () => ({
  apiFetch: vi.fn(),
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
});
