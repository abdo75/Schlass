import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { ClientCreatePage } from "../ClientCreatePage";
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
        <ClientCreatePage />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe("ClientCreatePage", () => {
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
  });

  it("submits the form and reveals the secret modal on success", async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      client_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      client_secret: "plaintext-shown-once",
      client: {},
    });

    render(wrap());

    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "my-portal" },
    });
    fireEvent.change(screen.getByPlaceholderText("https://..."), {
      target: { value: "https://portal.example.com/cb" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^Create$/ }));

    await waitFor(() =>
      expect(screen.getByText("plaintext-shown-once")).toBeInTheDocument(),
    );
    expect(apiFetch).toHaveBeenCalledWith(
      "/api/clients",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("renders all four scopes checked by default", () => {
    render(wrap());
    // Use getAllByLabelText to handle overlapping description text
    // (e.g. "offline_access" appears in the refresh_token grant description too)
    const checkboxes = screen.getAllByRole("checkbox");
    // Scopes: openid, profile, email, offline_access — first 4 checkboxes
    // Grants: authorization_code, refresh_token — next 2
    expect(checkboxes).toHaveLength(6);
    // All should be checked by default
    checkboxes.forEach((cb) => expect(cb).toBeChecked());
  });
});
