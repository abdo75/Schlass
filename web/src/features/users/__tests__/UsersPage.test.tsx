import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { UsersPage } from "../UsersPage";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as usersApi from "../api";
import * as authApi from "@/features/auth/api";

vi.mock("../api");
vi.mock("@/features/auth/api");

function wrap() {
  return (
    <MemoryRouter>
      <AuthProvider>
        <UsersPage />
      </AuthProvider>
    </MemoryRouter>
  );
}

const mkUsers = (count: number) =>
  Array.from({ length: count }, (_, i) => ({
    id: `u-${i}`,
    email: `user${i}@example.com`,
    role: i === 0 ? "super_admin" : "user",
    status: i === 2 ? "disabled" : "active",
    force_password_change: false,
    force_mfa_enrollment: false,
    created_at: new Date(Date.now() - i * 60000).toISOString(),
  }));

describe("UsersPage", () => {
  beforeEach(() => {
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: {
        id: "u-0",
        email: "user0@example.com",
        role: "super_admin",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
  });

  it("shows skeleton until data loads", () => {
    vi.mocked(usersApi.listUsers).mockReturnValue(new Promise(() => {}));
    render(wrap());
    expect(screen.queryByText(/user0@example.com/)).not.toBeInTheDocument();
  });

  it("renders rows and marks self with 'you'", async () => {
    vi.mocked(usersApi.listUsers).mockResolvedValue({
      users: mkUsers(3) as never,
      total: 3,
      limit: 10,
      offset: 0,
    });
    render(wrap());
    // user0 appears in the table row
    expect(
      await screen.findAllByText("user0@example.com"),
    ).not.toHaveLength(0);
    expect(screen.getByText("user1@example.com")).toBeInTheDocument();
    expect(screen.getByText(/you/i)).toBeInTheDocument();
  });

  it("triggers search on input", async () => {
    vi.mocked(usersApi.listUsers).mockResolvedValue({
      users: mkUsers(1) as never,
      total: 1,
      limit: 10,
      offset: 0,
    });
    render(wrap());
    // wait for table row to appear
    await screen.findAllByText("user0@example.com");
    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/search/i), "foo");
    await waitFor(() => {
      const calls = vi.mocked(usersApi.listUsers).mock.calls;
      const lastCall = calls[calls.length - 1];
      expect(lastCall[2]).toBe("foo");
    });
  });
});
