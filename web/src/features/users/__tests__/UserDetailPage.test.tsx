import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import "@/i18n";
import { UserDetailPage } from "../UserDetailPage";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as usersApi from "../api";
import * as authApi from "@/features/auth/api";

vi.mock("../api");
vi.mock("@/features/auth/api");

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual =
    await vi.importActual<typeof import("react-router-dom")>(
      "react-router-dom",
    );
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

type DetailResponse = Awaited<ReturnType<typeof usersApi.getUser>>;

function makeDetail(
  overrides: Partial<DetailResponse["user"]> = {},
  sessions: DetailResponse["sessions"] = [],
): DetailResponse {
  const base: DetailResponse["user"] = {
    id: "user-1",
    email: "target@example.com",
    role: "user",
    force_password_change: false,
    force_mfa_enrollment: false,
    status: "active",
    created_at: "2026-04-14T12:00:00Z",
  };
  return {
    user: { ...base, ...overrides },
    sessions,
  };
}

const ME_ADMIN = {
  id: "admin-1",
  email: "admin@example.com",
  role: "super_admin",
  force_password_change: false,
  force_mfa_enrollment: false,
};

function renderPage(id = "user-1") {
  return render(
    <MemoryRouter initialEntries={[`/admin/users/${id}`]}>
      <AuthProvider>
        <Routes>
          <Route path="/admin/users/:id" element={<UserDetailPage />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("UserDetailPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
    vi.mocked(authApi.getMe).mockResolvedValue({ user: ME_ADMIN });
  });

  it("renders profile card, actions card, and sessions card in view mode", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail(
        { email: "alice@example.com", role: "super_admin" },
        [
          {
            token: "tok-1",
            created_at: "2026-04-14T10:00:00Z",
            last_seen_at: "2026-04-14T12:00:00Z",
            ip_address: "10.0.0.1",
            user_agent: "Mozilla/5.0 (Macintosh) Firefox/120",
          },
        ],
      ),
    );

    renderPage();

    // Page title renders email
    expect(
      await screen.findByText("alice@example.com", { selector: ".text-lg" }),
    ).toBeInTheDocument();

    // Actions card visible
    expect(screen.getByText(/actions/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /reset password/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /disable user/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /delete/i }),
    ).toBeInTheDocument();

    // Sessions card visible with session row
    expect(screen.getByText(/active sessions/i)).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1")).toBeInTheDocument();

    // Edit button present in view mode
    expect(
      screen.getByRole("button", { name: /^edit$/i }),
    ).toBeInTheDocument();
  });

  it("shows self-view variant: 'This is you', hides Disable/Delete, shows change password link", async () => {
    // The current user IS the target user
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({ id: "admin-1", email: "admin@example.com", role: "super_admin" }),
    );

    renderPage("admin-1");

    // Wait for page to load (Actions heading appears when data is ready)
    await screen.findByText(/actions/i);

    // "This is you" marker
    expect(screen.getByText(/this is you/i)).toBeInTheDocument();

    // No Disable/Delete buttons
    expect(
      screen.queryByRole("button", { name: /disable user/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /delete/i }),
    ).not.toBeInTheDocument();

    // Change your password link present
    expect(screen.getByText(/change your password/i)).toBeInTheDocument();

    // No Edit button
    expect(
      screen.queryByRole("button", { name: /^edit$/i }),
    ).not.toBeInTheDocument();
  });

  it("edit mode: clicking Edit swaps to Cancel + Save, fields become inputs, actions card is dimmed", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({ email: "old@example.com", role: "user" }),
    );
    vi.mocked(usersApi.updateUser).mockResolvedValue({
      user: {
        id: "user-1",
        email: "new@example.com",
        role: "super_admin",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });

    renderPage();
    const user = userEvent.setup();

    await screen.findByTestId("actions-card");
    await user.click(screen.getByRole("button", { name: /^edit$/i }));

    // Edit button gone, Cancel + Save appear
    expect(
      screen.queryByRole("button", { name: /^edit$/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /cancel/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /save/i }),
    ).toBeInTheDocument();

    // Email input is present and editable
    const emailInput = screen.getByLabelText(/email/i);
    expect(emailInput).toBeInTheDocument();

    // Actions card is dimmed
    const actionsCard = screen.getByTestId("actions-card");
    expect(actionsCard).toHaveClass("opacity-45");
    expect(actionsCard).toHaveClass("pointer-events-none");

    // Save calls updateUser
    await user.clear(emailInput);
    await user.type(emailInput, "new@example.com");
    await user.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => {
      expect(usersApi.updateUser).toHaveBeenCalledWith("user-1", {
        email: "new@example.com",
        role: "user",
      });
    });
  });

  it("disabled variant: Enable button shown instead of Disable, sessions empty state", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({ status: "disabled" }),
    );
    vi.mocked(usersApi.enableUser).mockResolvedValue();

    renderPage();

    await screen.findByTestId("actions-card");

    // Enable instead of Disable
    expect(
      screen.queryByRole("button", { name: /disable user/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /enable user/i }),
    ).toBeInTheDocument();

    // Sessions empty state
    expect(screen.getByText(/no active sessions/i)).toBeInTheDocument();
    expect(
      screen.getByText(/sessions were terminated/i),
    ).toBeInTheDocument();
  });

  it("not-found renders centered empty state with 'Back to users'", async () => {
    vi.mocked(usersApi.getUser).mockRejectedValue({
      code: "USER_NOT_FOUND",
      message: "not found",
      status: 404,
    });

    renderPage("nonexistent");

    // Wait for the not-found state
    expect(
      await screen.findByText(/user not found/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/deleted by another administrator/i),
    ).toBeInTheDocument();

    const backLink = screen.getByRole("link", { name: /back to users/i });
    expect(backLink).toHaveAttribute("href", "/admin/users");
  });

  it("reset password flow: confirm dialog then TempPasswordModal", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(makeDetail());
    vi.mocked(usersApi.resetUserPassword).mockResolvedValue({
      temporary_password: "GenPass999!",
    });

    renderPage();
    const user = userEvent.setup();
    await screen.findByTestId("actions-card");

    // Click reset password in actions card
    await user.click(screen.getByRole("button", { name: /reset password/i }));

    // Confirm dialog appears -- find the confirm button inside the dialog
    const dialog = await screen.findByRole("dialog");
    const confirmBtn = within(dialog).getByRole("button", {
      name: /^reset password$/i,
    });
    await user.click(confirmBtn);

    // API called
    await waitFor(() => {
      expect(usersApi.resetUserPassword).toHaveBeenCalledWith("user-1");
    });

    // TempPasswordModal appears with the generated password
    await waitFor(() => {
      expect(screen.getByText("GenPass999!")).toBeInTheDocument();
    });
  });

  it("delete flow: confirm dialog then navigates to /admin/users", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(makeDetail());
    vi.mocked(usersApi.deleteUser).mockResolvedValue();

    renderPage();
    const user = userEvent.setup();
    await screen.findByTestId("actions-card");

    await user.click(screen.getByRole("button", { name: /delete/i }));
    const confirmBtn = await screen.findByRole("button", {
      name: /delete permanently/i,
    });
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(usersApi.deleteUser).toHaveBeenCalledWith("user-1");
    });
    await waitFor(() => {
      expect(navigateMock).toHaveBeenCalledWith("/admin/users");
    });
  });

  it("disable flow: confirm dialog then refetches user", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(makeDetail());
    vi.mocked(usersApi.disableUser).mockResolvedValue();

    renderPage();
    const user = userEvent.setup();
    await screen.findByTestId("actions-card");

    await user.click(screen.getByRole("button", { name: /disable user/i }));
    // Find the confirm button inside the dialog
    const dialog = await screen.findByRole("dialog");
    const confirmBtn = within(dialog).getByRole("button", {
      name: /^disable user$/i,
    });
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(usersApi.disableUser).toHaveBeenCalledWith("user-1");
    });
    await waitFor(() => {
      expect(usersApi.getUser).toHaveBeenCalledTimes(2);
    });
  });

  it("sessions table shows device info and per-session terminate button", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({}, [
        {
          token: "tok-aaa",
          created_at: "2026-04-14T10:00:00Z",
          last_seen_at: "2026-04-14T12:00:00Z",
          ip_address: "10.0.0.1",
          user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/120",
        },
      ]),
    );
    vi.mocked(usersApi.terminateSession).mockResolvedValue();

    renderPage();
    const user = userEvent.setup();
    const row = (await screen.findByText("10.0.0.1")).closest("tr");
    expect(row).not.toBeNull();

    await user.click(
      within(row as HTMLElement).getByRole("button", { name: /terminate/i }),
    );

    // Confirm dialog for single session
    const confirmBtn = await screen.findByRole("button", {
      name: /sign out device/i,
    });
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(usersApi.terminateSession).toHaveBeenCalledWith(
        "user-1",
        "tok-aaa",
      );
    });
  });

  it("shows Reset MFA button when target user is enrolled and current user has permission", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({ totp_enrolled_at: "2026-04-17T10:00:00Z" }),
    );
    vi.mocked(usersApi.resetMfa).mockResolvedValue({
      user: makeDetail({ totp_enrolled_at: null }).user,
    });

    renderPage();
    await screen.findByTestId("actions-card");

    expect(
      screen.getByRole("button", { name: /reset mfa/i }),
    ).toBeInTheDocument();
  });

  it("does not show Reset MFA button when target user is not enrolled", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({ totp_enrolled_at: undefined }),
    );

    renderPage();
    await screen.findByTestId("actions-card");

    expect(
      screen.queryByRole("button", { name: /reset mfa/i }),
    ).not.toBeInTheDocument();
  });

  it("Reset MFA flow: confirm dialog then calls resetMfa", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({ totp_enrolled_at: "2026-04-17T10:00:00Z" }),
    );
    vi.mocked(usersApi.resetMfa).mockResolvedValue({
      user: makeDetail({ totp_enrolled_at: null }).user,
    });

    renderPage();
    const user = userEvent.setup();
    await screen.findByTestId("actions-card");

    await user.click(screen.getByRole("button", { name: /reset mfa/i }));

    // Confirm dialog appears
    const dialog = await screen.findByRole("dialog");
    const confirmBtn = within(dialog).getByRole("button", {
      name: /reset mfa/i,
    });
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(usersApi.resetMfa).toHaveBeenCalledWith("user-1");
    });
  });

  it("terminate all sessions calls terminateAllSessions and refetches", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({}, [
        {
          token: "tok-1",
          created_at: "2026-04-14T10:00:00Z",
          last_seen_at: "2026-04-14T12:00:00Z",
          ip_address: "10.0.0.1",
          user_agent: "Mozilla/5.0 Chrome",
        },
      ]),
    );
    vi.mocked(usersApi.terminateAllSessions).mockResolvedValue();

    renderPage();
    const user = userEvent.setup();
    await screen.findByText("10.0.0.1");

    await user.click(
      screen.getByRole("button", { name: /terminate all/i }),
    );

    const confirmBtn = await screen.findByRole("button", {
      name: /sign out everywhere/i,
    });
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(usersApi.terminateAllSessions).toHaveBeenCalledWith("user-1");
    });
    await waitFor(() => {
      expect(usersApi.getUser).toHaveBeenCalledTimes(2);
    });
  });
});
