import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import "@/i18n";
import { AdminLayout, AdminPageHeader } from "../AdminLayout";
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

  it("renders Clients, Signing keys, Audit, and Settings nav items without 'coming soon'", async () => {
    render(wrap());
    await screen.findByText("Schlass");
    expect(screen.getByRole("link", { name: /clients/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /signing keys/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /audit/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /settings/i })).toBeInTheDocument();
    expect(screen.queryByText(/soon/i)).not.toBeInTheDocument();
  });

  it("renders the outlet content", async () => {
    render(wrap());
    expect(await screen.findByText(/users outlet content/i)).toBeInTheDocument();
  });

  it("renders the outlet content inside the main column (no persistent top bar)", async () => {
    render(wrap());
    // AdminLayout itself no longer renders a top bar — UserMenuPopover lives in
    // AdminPageHeader which individual pages render. Just verify the outlet loads.
    expect(await screen.findByText(/users outlet content/i)).toBeInTheDocument();
  });
});

describe("AdminPageHeader breadcrumbPath", () => {
  // AdminPageHeader renders UserMenuPopover which calls useAuth — wrap with AuthProvider.
  beforeEach(() => {
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: { id: "1", email: "admin@test.local", role: "super_admin", force_password_change: false, force_mfa_enrollment: false },
    });
  });

  it("renders the path as a title-scale breadcrumb with links to parents", () => {
    render(
      <MemoryRouter>
        <AuthProvider>
          <AdminPageHeader
            breadcrumbPath={[
              { label: "Users", to: "/admin/users" },
              { label: "alice@example.com" },
            ]}
          />
        </AuthProvider>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: /users/i })).toHaveAttribute("href", "/admin/users");
    expect(screen.getByText(/alice@example\.com/)).toBeInTheDocument();
  });

  it("does not render a separate title when breadcrumbPath is used", () => {
    const { container } = render(
      <MemoryRouter>
        <AuthProvider>
          <AdminPageHeader
            breadcrumbPath={[{ label: "Users" }]}
            title="Should not render"
          />
        </AuthProvider>
      </MemoryRouter>,
    );
    expect(container.textContent).not.toContain("Should not render");
  });
});
