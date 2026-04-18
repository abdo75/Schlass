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

  it("renders the persistent top bar with user menu trigger", async () => {
    render(wrap());
    // UserMenuPopover in the top bar shows the logged-in email as a button
    expect(await screen.findByRole("button", { name: /admin@test.local/i })).toBeInTheDocument();
  });
});

describe("AdminPageHeader breadcrumbPath", () => {
  it("renders the path as a title-scale breadcrumb with links to parents", () => {
    render(
      <MemoryRouter>
        <AdminPageHeader
          breadcrumbPath={[
            { label: "Users", to: "/admin/users" },
            { label: "alice@example.com" },
          ]}
        />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: /users/i })).toHaveAttribute("href", "/admin/users");
    expect(screen.getByText(/alice@example\.com/)).toBeInTheDocument();
  });

  it("does not render a separate title when breadcrumbPath is used", () => {
    const { container } = render(
      <MemoryRouter>
        <AdminPageHeader
          breadcrumbPath={[{ label: "Users" }]}
          title="Should not render"
        />
      </MemoryRouter>,
    );
    expect(container.textContent).not.toContain("Should not render");
  });
});
