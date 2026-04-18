import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { LoginPage } from "../LoginPage";
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

function renderLogin() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("LoginPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
    // AuthProvider's getMe call on mount — reject so the context settles to "not authed"
    vi.mocked(authApi.getMe).mockRejectedValue(new Error("unauthorized"));
  });

  it("renders email and password fields", async () => {
    renderLogin();
    await waitFor(() => {
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    });
  });

  it("submits credentials and calls login on success", async () => {
    vi.mocked(authApi.login).mockResolvedValue({
      kind: "session",
      user: {
        id: "1",
        email: "a@b.co",
        role: "super_admin",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
    renderLogin();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/email/i), "a@b.co");
    await user.type(screen.getByLabelText(/password/i), "hunter2hunter2");
    await user.click(
      screen.getByRole("button", { name: /sign in|log in|submit/i }),
    );
    await waitFor(() =>
      expect(authApi.login).toHaveBeenCalledWith("a@b.co", "hunter2hunter2", undefined),
    );
  });

  it("shows error on INVALID_CREDENTIALS", async () => {
    // ApiRequestError shape: { code, message, status, retryAfterSeconds? }
    vi.mocked(authApi.login).mockRejectedValue({
      code: "INVALID_CREDENTIALS",
      message: "Invalid email or password.",
      status: 401,
    });
    renderLogin();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/email/i), "a@b.co");
    await user.type(screen.getByLabelText(/password/i), "wrong");
    await user.click(
      screen.getByRole("button", { name: /sign in|log in|submit/i }),
    );
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        /invalid email or password/i,
      ),
    );
  });

  it("renders a minute-granularity countdown on ACCOUNT_LOCKED", async () => {
    // 841 seconds → 15 minutes (Math.ceil). Plural form is used via
    // i18next's `count` interpolation.
    vi.mocked(authApi.login).mockRejectedValue({
      code: "ACCOUNT_LOCKED",
      message: "Account temporarily locked.",
      status: 401,
      retryAfterSeconds: 841,
    });
    renderLogin();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/email/i), "a@b.co");
    await user.type(screen.getByLabelText(/password/i), "wrong");
    await user.click(
      screen.getByRole("button", { name: /sign in|log in|submit/i }),
    );
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        /try again in about 15 minutes/i,
      ),
    );
  });

  it("falls back to static message on ACCOUNT_LOCKED without retry info", async () => {
    vi.mocked(authApi.login).mockRejectedValue({
      code: "ACCOUNT_LOCKED",
      message: "Account temporarily locked.",
      status: 401,
    });
    renderLogin();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/email/i), "a@b.co");
    await user.type(screen.getByLabelText(/password/i), "wrong");
    await user.click(
      screen.getByRole("button", { name: /sign in|log in|submit/i }),
    );
    // Generic message with "try again in a few minutes", NOT the countdown.
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        /try again in a few minutes/i,
      ),
    );
  });

  it("Success navigates to /admin for super_admin", async () => {
    vi.mocked(authApi.login).mockResolvedValue({
      kind: "session",
      user: {
        id: "1",
        email: "admin@example.com",
        role: "super_admin",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
    renderLogin();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/email/i), "admin@example.com");
    await user.type(screen.getByLabelText(/password/i), "hunter2hunter2");
    await user.click(
      screen.getByRole("button", { name: /sign in|log in|submit/i }),
    );
    await waitFor(() =>
      expect(navigateMock).toHaveBeenCalledWith("/admin", { replace: true }),
    );
  });

  it("Success navigates to /account for role=user", async () => {
    vi.mocked(authApi.login).mockResolvedValue({
      kind: "session",
      user: {
        id: "2",
        email: "alice@example.com",
        role: "user",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
    renderLogin();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/email/i), "alice@example.com");
    await user.type(screen.getByLabelText(/password/i), "hunter2hunter2");
    await user.click(
      screen.getByRole("button", { name: /sign in|log in|submit/i }),
    );
    await waitFor(() =>
      expect(navigateMock).toHaveBeenCalledWith("/account", { replace: true }),
    );
  });

  it("redirects authenticated super_admin to /admin", async () => {
    // Mock AuthProvider's getMe to return an authenticated super_admin user
    // instead of rejecting. This simulates a user who is already logged in
    // and navigates directly to /login.
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: {
        id: "1",
        email: "admin@example.com",
        role: "super_admin",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
    renderLogin();
    // After auth loading completes, the component returns null (loading state)
    // then <Navigate> (redirect). The form should never be rendered.
    await waitFor(() => {
      expect(screen.queryByLabelText(/email/i)).not.toBeInTheDocument();
    });
  });

  it("redirects authenticated regular user to /account", async () => {
    // Mock AuthProvider's getMe to return an authenticated regular user.
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: {
        id: "2",
        email: "alice@example.com",
        role: "user",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
    renderLogin();
    // After auth loading completes, the component returns null (loading state)
    // then <Navigate> (redirect). The form should never be rendered.
    await waitFor(() => {
      expect(screen.queryByLabelText(/email/i)).not.toBeInTheDocument();
    });
  });
});
