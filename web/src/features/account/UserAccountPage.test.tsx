import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import React from "react";
import { I18nextProvider } from "react-i18next";
import { AuthContext } from "@/features/auth/AuthContext";
import { UserAccountPage } from "./UserAccountPage";
import type { AuthUser } from "@/features/auth/api";
import * as authApi from "@/features/auth/api";
import i18n from "@/i18n/index";

function withProviders(
  user: AuthUser | null,
  logout = vi.fn(),
  refreshUser = vi.fn().mockResolvedValue(null),
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
          refreshUser,
        }}
      >
        <MemoryRouter>{children}</MemoryRouter>
      </AuthContext.Provider>
    </I18nextProvider>
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
});

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
    // Email appears in both the identity hero h2 and the AdminPageHeader UserMenuPopover trigger
    expect(screen.getAllByText(/alice@example\.com/).length).toBeGreaterThan(0);
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

  it("shows PROFILE, SECURITY and SESSION section labels", () => {
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));
    expect(screen.getByText("Profile")).toBeInTheDocument();
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
    // Disable button present (replaces the old admin-contact footnote)
    expect(
      screen.getByRole("button", { name: /disable two-factor/i }),
    ).toBeInTheDocument();
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

  it("shows Disable button when user is enrolled", () => {
    const wrap = withProviders(enrolledUser);
    render(wrap(<UserAccountPage />));
    expect(
      screen.getByRole("button", { name: /disable two-factor/i }),
    ).toBeInTheDocument();
  });

  it("does not show Disable button when user is not enrolled", () => {
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));
    expect(
      screen.queryByRole("button", { name: /disable two-factor/i }),
    ).not.toBeInTheDocument();
  });

  it("opens the disable dialog when Disable button is clicked", async () => {
    const wrap = withProviders(enrolledUser);
    render(wrap(<UserAccountPage />));
    await userEvent.click(
      screen.getByRole("button", { name: /disable two-factor/i }),
    );
    await waitFor(() => {
      expect(
        screen.getByRole("dialog", { name: /disable two-factor/i }),
      ).toBeInTheDocument();
    });
  });

  it("shows email in the Profile section", () => {
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));
    // The email address appears as display text under the Profile heading
    const profileHeading = screen.getByText("Profile");
    expect(profileHeading).toBeInTheDocument();
    // Multiple instances of the email may exist (hero + profile row); at least one must be present
    expect(screen.getAllByText(/alice@example\.com/).length).toBeGreaterThan(0);
    // Edit button is visible in display mode
    expect(screen.getByRole("button", { name: /^edit$/i })).toBeInTheDocument();
  });

  it("clicking Edit swaps the email display for an input", async () => {
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));
    await userEvent.click(screen.getByRole("button", { name: /^edit$/i }));
    // The inline email input should now be present
    const input = screen.getByRole("textbox", { name: /email address/i });
    expect(input).toBeInTheDocument();
    expect((input as HTMLInputElement).value).toBe("alice@example.com");
    // Save button should be disabled because value is unchanged
    expect(screen.getByRole("button", { name: /^save$/i })).toBeDisabled();
    // Cancel button is visible
    expect(screen.getByRole("button", { name: /^cancel$/i })).toBeInTheDocument();
  });

  it("Save calls updateProfile and exits edit mode", async () => {
    const mockUpdateProfile = vi
      .spyOn(authApi, "updateProfile")
      .mockResolvedValue({ user: { ...regularUser, email: "new@example.com" } });
    const refreshUser = vi.fn().mockResolvedValue({ ...regularUser, email: "new@example.com" });
    const wrap = withProviders(regularUser, vi.fn(), refreshUser);
    render(wrap(<UserAccountPage />));

    await userEvent.click(screen.getByRole("button", { name: /^edit$/i }));
    const input = screen.getByRole("textbox", { name: /email address/i });
    await userEvent.clear(input);
    await userEvent.type(input, "new@example.com");

    const saveBtn = screen.getByRole("button", { name: /^save$/i });
    expect(saveBtn).not.toBeDisabled();
    await userEvent.click(saveBtn);

    await waitFor(() => {
      expect(mockUpdateProfile).toHaveBeenCalledWith({ email: "new@example.com" });
      expect(refreshUser).toHaveBeenCalledTimes(1);
    });
    // Edit mode should have collapsed — input gone
    await waitFor(() => {
      expect(screen.queryByRole("textbox", { name: /email address/i })).not.toBeInTheDocument();
    });
  });

  it("shows error message on save failure", async () => {
    vi.spyOn(authApi, "updateProfile").mockRejectedValue({ code: "EMAIL_ALREADY_EXISTS" });
    const wrap = withProviders(regularUser);
    render(wrap(<UserAccountPage />));

    await userEvent.click(screen.getByRole("button", { name: /^edit$/i }));
    const input = screen.getByRole("textbox", { name: /email address/i });
    await userEvent.clear(input);
    await userEvent.type(input, "taken@example.com");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => {
      const alert = screen.getByRole("alert");
      expect(alert).toBeInTheDocument();
      expect(alert.textContent).toMatch(/A user with that email already exists/i);
    });
    // Edit mode stays open so user can correct the email
    expect(screen.getByRole("textbox", { name: /email address/i })).toBeInTheDocument();
  });
});
