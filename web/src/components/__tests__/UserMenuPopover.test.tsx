import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { UserMenuPopover } from "../UserMenuPopover";
import { AuthContext } from "@/features/auth/AuthContext";
import type { AuthUser } from "@/features/auth/api";
import * as authApi from "@/features/auth/api";

vi.mock("@/features/auth/api");

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const adminUser: AuthUser = {
  id: "1",
  email: "admin@test.local",
  role: "super_admin",
  force_password_change: false,
  force_mfa_enrollment: false,
};

const regularUser: AuthUser = {
  id: "2",
  email: "user@test.local",
  role: "user",
  force_password_change: false,
  force_mfa_enrollment: false,
};

type AuthContextValue = NonNullable<React.ComponentProps<typeof AuthContext.Provider>["value"]>;

function makeAuthValue(user: AuthUser | null): AuthContextValue {
  return {
    user,
    loading: false,
    login: vi.fn() as AuthContextValue["login"],
    logout: vi.fn() as AuthContextValue["logout"],
    refreshUser: vi.fn() as AuthContextValue["refreshUser"],
  };
}

function renderAtPath(path: string, user: AuthUser | null) {
  return render(
    <AuthContext.Provider value={makeAuthValue(user)}>
      <MemoryRouter initialEntries={[path]}>
        <UserMenuPopover />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

async function openPopover(emailPattern: RegExp) {
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: emailPattern }));
  return user;
}

describe("UserMenuPopover", () => {
  beforeEach(() => {
    navigateMock.mockReset();
  });

  it("renders the pill trigger closed by default", async () => {
    renderAtPath("/admin/users", adminUser);
    expect(await screen.findByText("admin@test.local")).toBeInTheDocument();
    expect(screen.queryByText(/theme/i)).not.toBeInTheDocument();
  });

  it("opens the popover on click with theme + language + actions", async () => {
    renderAtPath("/admin/users", adminUser);
    await openPopover(/admin@test.local/i);
    expect(screen.getByText(/theme/i)).toBeInTheDocument();
    expect(screen.getByText(/language/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /my account/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
  });

  it("calls logout and navigates to /login on Sign out", async () => {
    vi.mocked(authApi.logout).mockResolvedValue(undefined);
    const authValue = makeAuthValue(adminUser);
    render(
      <AuthContext.Provider value={authValue}>
        <MemoryRouter initialEntries={["/admin/users"]}>
          <UserMenuPopover />
        </MemoryRouter>
      </AuthContext.Provider>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /admin@test.local/i }));
    await user.click(screen.getByRole("button", { name: /sign out/i }));
    await vi.waitFor(() => expect(authValue.logout).toHaveBeenCalled());
    await vi.waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/login", { replace: true }));
  });
});

describe("UserMenuPopover contextual label", () => {
  beforeEach(() => {
    navigateMock.mockReset();
  });

  it("shows 'My Account' on /admin/users for super_admin", async () => {
    renderAtPath("/admin/users", adminUser);
    await openPopover(/admin@test.local/i);
    const link = screen.getByRole("link", { name: /my account/i });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute("href", "/account");
  });

  it("shows 'My Account' on /change-password for super_admin", async () => {
    renderAtPath("/change-password", adminUser);
    await openPopover(/admin@test.local/i);
    const link = screen.getByRole("link", { name: /my account/i });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute("href", "/account");
  });

  it("shows 'My Account' on /change-password for regular user", async () => {
    renderAtPath("/change-password", regularUser);
    await openPopover(/user@test.local/i);
    const link = screen.getByRole("link", { name: /my account/i });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute("href", "/account");
  });

  it("shows 'Admin Panel' on /account for super_admin", async () => {
    renderAtPath("/account", adminUser);
    await openPopover(/admin@test.local/i);
    const link = screen.getByRole("link", { name: /admin panel/i });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute("href", "/admin/users");
  });

  it("hides the entry on /account for regular user", async () => {
    renderAtPath("/account", regularUser);
    await openPopover(/user@test.local/i);
    expect(screen.queryByRole("link", { name: /my account|admin panel/i })).not.toBeInTheDocument();
  });

  it("closes the popover when the contextual link is clicked", async () => {
    renderAtPath("/admin/users", adminUser);
    const ue = await openPopover(/admin@test.local/i);
    const link = screen.getByRole("link", { name: /my account/i });
    await ue.click(link);
    expect(screen.queryByText(/theme/i)).not.toBeInTheDocument();
  });
});
