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
          login: async () => (user ?? ({ id: "", email: "", role: "user", force_password_change: false } as AuthUser)),
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
    const link = screen.getByRole("link", { name: /change password/i });
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
});
