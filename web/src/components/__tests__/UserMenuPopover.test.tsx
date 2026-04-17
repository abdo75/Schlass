import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { UserMenuPopover } from "../UserMenuPopover";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("@/features/auth/api");

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

function wrap(ui: React.ReactNode) {
  return (
    <MemoryRouter>
      <AuthProvider>{ui}</AuthProvider>
    </MemoryRouter>
  );
}

describe("UserMenuPopover", () => {
  beforeEach(() => {
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: {
        id: "1",
        email: "admin@test.local",
        role: "super_admin",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
    navigateMock.mockReset();
  });

  it("renders the pill trigger closed by default", async () => {
    render(wrap(<UserMenuPopover />));
    expect(await screen.findByText("admin@test.local")).toBeInTheDocument();
    expect(screen.queryByText(/theme/i)).not.toBeInTheDocument();
  });

  it("opens the popover on click with theme + language + actions", async () => {
    render(wrap(<UserMenuPopover />));
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /admin@test.local/i }));
    expect(screen.getByText(/theme/i)).toBeInTheDocument();
    expect(screen.getByText(/language/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /change password/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
  });

  it("navigates to /change-password when Change password is clicked", async () => {
    render(wrap(<UserMenuPopover />));
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /admin@test.local/i }));
    await user.click(screen.getByRole("button", { name: /change password/i }));
    expect(navigateMock).toHaveBeenCalledWith("/change-password");
  });

  it("calls logout and navigates to /login on Sign out", async () => {
    vi.mocked(authApi.logout).mockResolvedValue(undefined);
    render(wrap(<UserMenuPopover />));
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /admin@test.local/i }));
    await user.click(screen.getByRole("button", { name: /sign out/i }));
    await vi.waitFor(() => expect(authApi.logout).toHaveBeenCalled());
    await vi.waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/login", { replace: true }));
  });
});
