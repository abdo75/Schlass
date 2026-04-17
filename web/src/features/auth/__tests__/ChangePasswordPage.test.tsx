import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ChangePasswordPage } from "../ChangePasswordPage";
import * as authApi from "../api";
import { AuthProvider } from "../AuthContext";

vi.mock("../api");

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

/**
 * Wait for the page to settle after getMe resolves, then return fresh
 * element references so tests aren't affected by the transient initial
 * render where user=null switches to user loaded.
 */
async function waitForStableForm() {
  // findByLabelText waits until the element appears. But because the page
  // transitions from self-service (user=null) to forced/self-service once
  // getMe resolves, the first reference can be stale. We wait for the
  // final stable state by waiting for getMe calls to settle.
  // Using findByLabelText on the first call will settle the page; we then
  // re-query synchronously to get the live reference.
  await screen.findByLabelText(/current password/i);
  // Wait one more tick for React to finish flushing the state update from
  // getMe resolution so we definitely have the final DOM.
  await new Promise((r) => setTimeout(r, 0));
  return {
    currentPw: screen.getByLabelText(/current password/i),
    newPw: screen.getByLabelText(/^new password$/i),
    confirmPw: screen.getByLabelText(/confirm new password/i),
    confirmBtn: screen.getByRole("button", { name: /confirm/i }),
  };
}

function renderForced() {
  vi.mocked(authApi.getMe).mockResolvedValue({
    user: {
      id: "1",
      email: "admin@example.com",
      role: "super_admin",
      force_password_change: true,
    },
  });
  return render(
    <MemoryRouter initialEntries={["/change-password"]}>
      <AuthProvider>
        <ChangePasswordPage />
      </AuthProvider>
    </MemoryRouter>,
  );
}

function renderSelfService() {
  vi.mocked(authApi.getMe).mockResolvedValue({
    user: {
      id: "1",
      email: "admin@example.com",
      role: "super_admin",
      force_password_change: false,
    },
  });
  return render(
    <MemoryRouter initialEntries={["/change-password"]}>
      <AuthProvider>
        <ChangePasswordPage />
      </AuthProvider>
    </MemoryRouter>,
  );
}

function renderSelfServiceAsRegularUser() {
  vi.mocked(authApi.getMe).mockResolvedValue({
    user: {
      id: "2",
      email: "alice@example.com",
      role: "user",
      force_password_change: false,
    },
  });
  return render(
    <MemoryRouter initialEntries={["/change-password"]}>
      <AuthProvider>
        <ChangePasswordPage />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("ChangePasswordPage — forced mode", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
  });

  it("renders inside AuthLayout: brand lockup 'Schlass' visible, no sidebar Users nav link", async () => {
    renderForced();
    await waitForStableForm();
    // After settling in forced mode, AuthLayout brand is present
    await waitFor(() =>
      expect(screen.getByText("Schlass")).toBeInTheDocument(),
    );
    // Sidebar Users nav link must NOT be present in forced mode
    expect(screen.queryByRole("link", { name: /users/i })).not.toBeInTheDocument();
  });

  it("renders three password fields and a Confirm button with no Cancel", async () => {
    renderForced();
    const { confirmBtn } = await waitForStableForm();
    expect(screen.getByLabelText(/^new password$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/confirm new password/i)).toBeInTheDocument();
    expect(confirmBtn).toBeInTheDocument();
    // No Cancel button in forced mode
    expect(screen.queryByRole("button", { name: /cancel/i })).not.toBeInTheDocument();
  });

  it("shows a mismatch error without calling the API when confirm differs", async () => {
    renderForced();
    const user = userEvent.setup();
    const { currentPw, newPw, confirmPw, confirmBtn } = await waitForStableForm();

    await user.type(currentPw, "OldPassword123");
    await user.type(newPw, "NewPassword123");
    await user.type(confirmPw, "Different123");
    await user.click(confirmBtn);

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/do not match/i),
    );
    expect(authApi.changePassword).not.toHaveBeenCalled();
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("calls changePassword, refreshes user, and navigates to /admin/users on success", async () => {
    vi.mocked(authApi.changePassword).mockResolvedValue(undefined);
    vi.mocked(authApi.getMe)
      .mockResolvedValueOnce({
        user: {
          id: "1",
          email: "admin@example.com",
          role: "super_admin",
          force_password_change: true,
        },
      })
      .mockResolvedValueOnce({
        user: {
          id: "1",
          email: "admin@example.com",
          role: "super_admin",
          force_password_change: false,
        },
      });

    render(
      <MemoryRouter initialEntries={["/change-password"]}>
        <AuthProvider>
          <ChangePasswordPage />
        </AuthProvider>
      </MemoryRouter>,
    );

    const user = userEvent.setup();
    const { currentPw, newPw, confirmPw, confirmBtn } = await waitForStableForm();

    await user.type(currentPw, "OldPassword123");
    await user.type(newPw, "NewPassword123");
    await user.type(confirmPw, "NewPassword123");
    await user.click(confirmBtn);

    await waitFor(() =>
      expect(authApi.changePassword).toHaveBeenCalledWith(
        "OldPassword123",
        "NewPassword123",
      ),
    );
    await waitFor(() =>
      expect(navigateMock).toHaveBeenCalledWith("/admin/users", {
        replace: true,
      }),
    );
    // getMe called once by AuthProvider on mount and once by refreshUser
    expect(authApi.getMe).toHaveBeenCalledTimes(2);
    // refreshUser must resolve BEFORE navigate
    const refreshOrder = vi.mocked(authApi.getMe).mock.invocationCallOrder[1];
    const navigateOrder = navigateMock.mock.invocationCallOrder[0];
    expect(refreshOrder).toBeLessThan(navigateOrder);
  });

  it("renders a translated error when the backend returns WRONG_CURRENT_PASSWORD", async () => {
    vi.mocked(authApi.changePassword).mockRejectedValue({
      code: "WRONG_CURRENT_PASSWORD",
      message: "wrong password",
      status: 400,
    });

    renderForced();
    const user = userEvent.setup();
    const { currentPw, newPw, confirmPw, confirmBtn } = await waitForStableForm();

    await user.type(currentPw, "WrongOld123");
    await user.type(newPw, "NewPassword123");
    await user.type(confirmPw, "NewPassword123");
    await user.click(confirmBtn);

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        /current password is incorrect/i,
      ),
    );
    expect(navigateMock).not.toHaveBeenCalled();
  });
});

describe("ChangePasswordPage — self-service mode", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
  });

  it("renders inside the admin shell: sidebar Users nav link visible", async () => {
    renderSelfService();
    await waitForStableForm();
    // Sidebar Users nav link is present in self-service mode
    expect(
      await screen.findByRole("link", { name: /users/i }),
    ).toBeInTheDocument();
  });

  it("renders Cancel and Confirm buttons", async () => {
    renderSelfService();
    const { confirmBtn } = await waitForStableForm();
    expect(confirmBtn).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();
  });

  it("Cancel navigates to /admin/users", async () => {
    renderSelfService();
    const user = userEvent.setup();
    await waitForStableForm();
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(navigateMock).toHaveBeenCalledWith("/admin/users", { replace: true });
  });

  it("Cancel navigates to /account for role=user", async () => {
    renderSelfServiceAsRegularUser();
    const user = userEvent.setup();
    await waitForStableForm();
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(navigateMock).toHaveBeenCalledWith("/account", { replace: true });
  });

  it("Success navigates to /account for role=user", async () => {
    vi.mocked(authApi.changePassword).mockResolvedValue(undefined);
    vi.mocked(authApi.getMe)
      .mockResolvedValueOnce({
        user: {
          id: "2",
          email: "alice@example.com",
          role: "user",
          force_password_change: false,
        },
      })
      .mockResolvedValueOnce({
        user: {
          id: "2",
          email: "alice@example.com",
          role: "user",
          force_password_change: false,
        },
      });

    render(
      <MemoryRouter initialEntries={["/change-password"]}>
        <AuthProvider>
          <ChangePasswordPage />
        </AuthProvider>
      </MemoryRouter>,
    );

    const user = userEvent.setup();
    const { currentPw, newPw, confirmPw, confirmBtn } = await waitForStableForm();

    await user.type(currentPw, "OldPassword123");
    await user.type(newPw, "NewPassword123");
    await user.type(confirmPw, "NewPassword123");
    await user.click(confirmBtn);

    await waitFor(() =>
      expect(navigateMock).toHaveBeenCalledWith("/account", { replace: true }),
    );
  });
});
