import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import "@/i18n";
import { AdminLayout } from "../AdminLayout";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("@/features/auth/api");

function wrap(path = "/admin/users") {
  return (
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route path="/admin" element={<AdminLayout />}>
            <Route path="users" element={<div>users outlet content</div>} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>
  );
}

describe("AdminLayout", () => {
  beforeEach(() => {
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: { id: "1", email: "admin@test.local", role: "super_admin", force_password_change: false, force_mfa_enrollment: false },
    });
  });

  it("renders the sidebar brand and Users nav item", async () => {
    render(wrap());
    expect(await screen.findByText("Schlass")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /users/i })).toBeInTheDocument();
  });

  it("does not render Clients, Audit, Settings, or 'coming soon'", async () => {
    render(wrap());
    await screen.findByText("Schlass");
    expect(screen.queryByText(/clients/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/audit/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/settings/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/soon/i)).not.toBeInTheDocument();
  });

  it("renders the outlet content", async () => {
    render(wrap());
    expect(await screen.findByText(/users outlet content/i)).toBeInTheDocument();
  });
});
