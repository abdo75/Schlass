import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { ClientsPage } from "../ClientsPage";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("@/lib/api", () => ({
  apiFetch: vi.fn(),
}));
vi.mock("@/features/auth/api");

import { apiFetch } from "@/lib/api";

function wrap(initialEntries = ["/admin/clients"]) {
  return (
    <MemoryRouter initialEntries={initialEntries}>
      <AuthProvider>
        <ClientsPage />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe("ClientsPage", () => {
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

  it("renders clients from the API", async () => {
    const now = new Date().toISOString();
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      clients: [
        {
          id: "11111111-1111-1111-1111-111111111111",
          name: "portal",
          client_type: "confidential",
          redirect_uris: ["https://x/cb"],
          allowed_grant_types: ["authorization_code"],
          allowed_scopes: ["openid"],
          token_endpoint_auth_method: "client_secret_post",
          status: "active",
          created_at: now,
          updated_at: now,
        },
      ],
    });

    render(wrap());

    await waitFor(() => expect(screen.getByText("portal")).toBeInTheDocument());
    expect(screen.getByText(/1 active/)).toBeInTheDocument();
  });
});
