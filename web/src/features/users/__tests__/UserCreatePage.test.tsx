import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { UserCreatePage } from "../UserCreatePage";
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

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <UserCreatePage />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("UserCreatePage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: {
        id: "admin-1",
        email: "admin@example.com",
        role: "super_admin",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
  });

  it("has email and role fields but NO password field", () => {
    renderPage();
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument();
    expect(screen.getByText(/role/i)).toBeInTheDocument();
  });

  it("submits email + role only, then shows the temp password modal", async () => {
    vi.mocked(usersApi.createUser).mockResolvedValue({
      user: {
        id: "new-user-123",
        email: "new@example.com",
        role: "user",
        force_password_change: true,
        force_mfa_enrollment: false,
      },
      temporary_password: "TempPass123!",
    });

    renderPage();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText(/email/i), "new@example.com");
    await user.click(screen.getByRole("button", { name: /create user/i }));

    await waitFor(() => {
      expect(usersApi.createUser).toHaveBeenCalledWith("new@example.com", "user");
    });

    await waitFor(() => {
      expect(screen.getByText("TempPass123!")).toBeInTheDocument();
    });

    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("navigates to the detail page when the modal is dismissed", async () => {
    vi.mocked(usersApi.createUser).mockResolvedValue({
      user: {
        id: "new-user-456",
        email: "another@example.com",
        role: "user",
        force_password_change: true,
        force_mfa_enrollment: false,
      },
      temporary_password: "AnotherPass1!",
    });

    renderPage();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText(/email/i), "another@example.com");
    await user.click(screen.getByRole("button", { name: /create user/i }));

    await waitFor(() => {
      expect(screen.getByText("AnotherPass1!")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: /done/i }));

    await waitFor(() => {
      expect(navigateMock).toHaveBeenCalledWith("/admin/users/new-user-456");
    });
  });

  it("renders backend error inline on failure", async () => {
    vi.mocked(usersApi.createUser).mockRejectedValue({
      code: "EMAIL_ALREADY_EXISTS",
      message: "duplicate",
      status: 409,
    });

    renderPage();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText(/email/i), "dup@example.com");
    await user.click(screen.getByRole("button", { name: /create user/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/already exists/i);
    });
    expect(navigateMock).not.toHaveBeenCalled();
  });
});
