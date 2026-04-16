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

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ChangePasswordPage />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("ChangePasswordPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
    // AuthProvider mounts and calls getMe — default to an authed user so the
    // provider settles without error. Tests that care about refreshUser assert
    // on getMe directly.
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: {
        id: "1",
        email: "admin@example.com",
        role: "super_admin",
        force_password_change: true,
      },
    });
  });

  it("renders three password inputs and a submit button", async () => {
    renderPage();
    expect(await screen.findByLabelText(/current password/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^new password$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/confirm new password/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /change password/i }),
    ).toBeInTheDocument();
  });

  it("shows a mismatch error without calling the API when confirm differs", async () => {
    renderPage();
    const user = userEvent.setup();

    await user.type(
      await screen.findByLabelText(/current password/i),
      "OldPassword123",
    );
    await user.type(
      screen.getByLabelText(/^new password$/i),
      "NewPassword123",
    );
    await user.type(
      screen.getByLabelText(/confirm new password/i),
      "Different123",
    );
    await user.click(
      screen.getByRole("button", { name: /change password/i }),
    );

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/do not match/i),
    );
    expect(authApi.changePassword).not.toHaveBeenCalled();
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("calls changePassword, refreshes user, and navigates to /admin on success", async () => {
    vi.mocked(authApi.changePassword).mockResolvedValue(undefined);
    // After the change the user no longer needs to force-change their password.
    vi.mocked(authApi.getMe).mockResolvedValueOnce({
      user: {
        id: "1",
        email: "admin@example.com",
        role: "super_admin",
        force_password_change: true,
      },
    });
    vi.mocked(authApi.getMe).mockResolvedValueOnce({
      user: {
        id: "1",
        email: "admin@example.com",
        role: "super_admin",
        force_password_change: false,
      },
    });

    renderPage();
    const user = userEvent.setup();

    await user.type(
      await screen.findByLabelText(/current password/i),
      "OldPassword123",
    );
    await user.type(
      screen.getByLabelText(/^new password$/i),
      "NewPassword123",
    );
    await user.type(
      screen.getByLabelText(/confirm new password/i),
      "NewPassword123",
    );
    await user.click(
      screen.getByRole("button", { name: /change password/i }),
    );

    await waitFor(() =>
      expect(authApi.changePassword).toHaveBeenCalledWith(
        "OldPassword123",
        "NewPassword123",
      ),
    );
    await waitFor(() =>
      expect(navigateMock).toHaveBeenCalledWith("/admin", { replace: true }),
    );
    // getMe is called once by the AuthProvider on mount and once by refreshUser
    // after the successful change.
    expect(authApi.getMe).toHaveBeenCalledTimes(2);
    // refreshUser must resolve BEFORE navigate, otherwise AuthGuard would still
    // see the stale force_password_change=true user and bounce back here.
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

    renderPage();
    const user = userEvent.setup();

    await user.type(
      await screen.findByLabelText(/current password/i),
      "WrongOld123",
    );
    await user.type(
      screen.getByLabelText(/^new password$/i),
      "NewPassword123",
    );
    await user.type(
      screen.getByLabelText(/confirm new password/i),
      "NewPassword123",
    );
    await user.click(
      screen.getByRole("button", { name: /change password/i }),
    );

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        /current password is incorrect/i,
      ),
    );
    expect(navigateMock).not.toHaveBeenCalled();
  });
});
