import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import React from "react";
import { I18nextProvider } from "react-i18next";
import { AuthContext } from "@/features/auth/AuthContext";
import { UserAccountPage } from "./UserAccountPage";
import type { AuthUser } from "@/features/auth/api";
import i18n from "@/i18n/index";

function withProviders(
  user: AuthUser | null,
  logout = vi.fn(),
): (children: ReactNode) => React.ReactElement {
  return (children) => (
    <I18nextProvider i18n={i18n}>
      <AuthContext.Provider
        value={{
          user,
          loading: false,
          // eslint-disable-next-line @typescript-eslint/require-await
          login: async () => ({ kind: "session" as const, user: user ?? ({ id: "", email: "", role: "user", force_password_change: false, force_mfa_enrollment: false } as AuthUser) }),
          logout,
          // eslint-disable-next-line @typescript-eslint/require-await
          refreshUser: async () => null,
        }}
      >
        <MemoryRouter>{children}</MemoryRouter>
      </AuthContext.Provider>
    </I18nextProvider>
  );
}

const regularUser: AuthUser = {
  id: "u1",
  email: "alice@example.com",
  role: "user",
  force_password_change: false,
  force_mfa_enrollment: false,
};

const enrolledUser: AuthUser = {
  id: "u2",
  email: "bob@example.com",
  role: "super_admin",
  force_password_change: false,
  force_mfa_enrollment: false,
  totp_enrolled_at: "2026-04-17T10:00:00Z",
  mfa: { unused_recovery_codes: 7 },
};

describe("UserAccountPage", () => {
  it("displays the signed-in user's email", () => {
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));
    expect(screen.getByText(/alice@example\.com/)).toBeInTheDocument();
  });

  it("has a change-password link pointing to /change-password", () => {
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));
    const link = screen.getByRole("link", { name: /^change$/i });
    expect(link).toHaveAttribute("href", "/change-password");
  });

  it("signs the user out when sign-out is clicked", async () => {
    const logout = vi.fn().mockResolvedValue(undefined);
    const wrap = withProviders(regularUser, logout);
    render(wrap(<UserAccountPage />));
    const button = screen.getByRole("button", { name: /sign out/i });
    await userEvent.click(button);
    expect(logout).toHaveBeenCalledTimes(1);
  });

  it("shows SECURITY and SESSION section labels", () => {
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));
    expect(screen.getByText("Security")).toBeInTheDocument();
    expect(screen.getByText("Session")).toBeInTheDocument();
  });

  it("shows 'Enabled' badge and recovery code count when user has totp_enrolled_at", () => {
    const wrap = withProviders(enrolledUser);
    render(wrap(<UserAccountPage />));
    // The Enabled badge is a span with uppercase styling
    const badge = screen.getAllByText(/enabled/i).find(
      (el) => el.tagName === "SPAN",
    );
    expect(badge).toBeInTheDocument();
    // Recovery codes text
    expect(screen.getByText(/7 recovery codes? remaining/i)).toBeInTheDocument();
    // Admin contact footnote
    expect(screen.getByText(/contact an administrator/i)).toBeInTheDocument();
  });

  it("does not show 'Enabled' badge when user has no totp_enrolled_at", () => {
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));
    // No span with "Enabled" badge text
    const badge = screen.queryAllByText(/^enabled$/i).find(
      (el) => el.tagName === "SPAN",
    );
    expect(badge).toBeUndefined();
  });

  it("shows Set up link pointing to /setup-mfa when not enrolled", () => {
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));
    const link = screen.getByRole("link", { name: /set up/i });
    expect(link).toHaveAttribute("href", "/setup-mfa");
  });
});
