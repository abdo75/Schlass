import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "@/i18n";
import { ClientDetailPage } from "../ClientDetailPage";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("@/lib/api", () => ({
  apiFetch: vi.fn(),
}));
vi.mock("@/features/auth/api");

import { apiFetch } from "@/lib/api";

const MOCK_CLIENT = {
  id: "client-uuid-1",
  name: "my-portal",
  client_type: "confidential" as const,
  redirect_uris: ["https://portal.example.com/cb"],
  allowed_grant_types: ["authorization_code", "refresh_token"],
  allowed_scopes: ["openid", "profile"],
  token_endpoint_auth_method: "client_secret_post",
  status: "active" as const,
  created_by_user_id: "user-1",
  created_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
  updated_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
};

function wrap(id = "client-uuid-1") {
  return (
    <MemoryRouter initialEntries={[`/admin/clients/${id}`]}>
      <AuthProvider>
        <Routes>
          <Route
            path="/admin/clients/:id"
            element={<ClientDetailPage />}
          />
        </Routes>
      </AuthProvider>
    </MemoryRouter>
  );
}

describe("ClientDetailPage", () => {
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

  it("renders client name, type, and client ID after load", async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      client: MOCK_CLIENT,
    });

    render(wrap());

    // Wait for h1 to appear (the header strip, not the breadcrumb span)
    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
        "my-portal",
      ),
    );

    // Identity section — "confidential" is the DOM text (CSS capitalize is visual only)
    expect(screen.getByText("confidential")).toBeInTheDocument();
    // Client ID is in a <code> element — use getAllByText since it may appear
    // in the breadcrumb too before data loads, use the code element query
    expect(screen.getByText("client-uuid-1")).toBeInTheDocument();

    // Redirect URI chip
    expect(
      screen.getByText("https://portal.example.com/cb"),
    ).toBeInTheDocument();

    // Scope chips — multiple "openid" occurrences possible, so use getAllByText
    const openidEls = screen.getAllByText("openid");
    expect(openidEls.length).toBeGreaterThan(0);
  });

  it("renders the danger zone with disable and delete buttons", async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      client: MOCK_CLIENT,
    });

    render(wrap());

    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
        "my-portal",
      ),
    );

    expect(screen.getByRole("button", { name: "Disable" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete" })).toBeInTheDocument();
  });

  it("opens delete confirm modal when Delete button is clicked", async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      client: MOCK_CLIENT,
    });

    render(wrap());

    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
        "my-portal",
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    // Modal should appear with type-to-confirm input
    expect(screen.getByPlaceholderText("my-portal")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Delete permanently" }),
    ).toBeDisabled();
  });

  it("enables the delete button only when client name is typed exactly", async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      client: MOCK_CLIENT,
    });

    render(wrap());

    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
        "my-portal",
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    const confirmInput = screen.getByPlaceholderText("my-portal");
    const deleteBtn = screen.getByRole("button", { name: "Delete permanently" });

    expect(deleteBtn).toBeDisabled();

    fireEvent.change(confirmInput, { target: { value: "my-portal" } });
    expect(deleteBtn).not.toBeDisabled();
  });

  it("shows Enable button when client is disabled", async () => {
    (apiFetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      client: { ...MOCK_CLIENT, status: "disabled" },
    });

    render(wrap());

    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
        "my-portal",
      ),
    );

    expect(screen.getByRole("button", { name: "Enable" })).toBeInTheDocument();
  });
});
