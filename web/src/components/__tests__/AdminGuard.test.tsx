import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { AuthContext } from "@/features/auth/AuthContext";
import { AdminGuard } from "@/components/AdminGuard";
import type { AuthUser } from "@/features/auth/api";

interface AuthState {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<AuthUser>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<AuthUser | null>;
}

function renderAtPath(path: string, user: AuthUser | null, loading = false) {
  const value: AuthState = {
    user,
    loading,
    // eslint-disable-next-line @typescript-eslint/require-await
    login: async () => (user ?? ({ id: "", email: "", role: "user", force_password_change: false } as AuthUser)),
    logout: async () => {},
    // eslint-disable-next-line @typescript-eslint/require-await
    refreshUser: async () => null,
  };
  return render(
    <AuthContext.Provider value={value}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/admin"
            element={
              <AdminGuard>
                <div data-testid="admin-content">admin</div>
              </AdminGuard>
            }
          />
          <Route path="/login" element={<div data-testid="login">login</div>} />
          <Route path="/account" element={<div data-testid="account">account</div>} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

const superAdmin: AuthUser = {
  id: "a1",
  email: "admin@x.com",
  role: "super_admin",
  force_password_change: false,
};
const regularUser: AuthUser = {
  id: "u1",
  email: "u@x.com",
  role: "user",
  force_password_change: false,
};

describe("AdminGuard", () => {
  it("renders children for super_admin", () => {
    renderAtPath("/admin", superAdmin);
    expect(screen.getByTestId("admin-content")).toBeInTheDocument();
  });

  it("redirects role=user to /account", () => {
    renderAtPath("/admin", regularUser);
    expect(screen.getByTestId("account")).toBeInTheDocument();
    expect(screen.queryByTestId("admin-content")).not.toBeInTheDocument();
  });

  it("redirects unauthenticated to /login", () => {
    renderAtPath("/admin", null);
    expect(screen.getByTestId("login")).toBeInTheDocument();
  });

  it("renders nothing while auth is loading", () => {
    const { container } = renderAtPath("/admin", null, true);
    expect(container.textContent).toBe("");
  });
});
