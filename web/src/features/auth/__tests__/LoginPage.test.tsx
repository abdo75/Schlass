import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { LoginPage } from "../LoginPage";
import * as authApi from "../api";
import { AuthProvider } from "../AuthContext";

vi.mock("../api");

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
      user: {
        id: "1",
        email: "a@b.co",
        role: "super_admin",
        force_password_change: false,
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
      expect(authApi.login).toHaveBeenCalledWith("a@b.co", "hunter2hunter2"),
    );
  });

  it("shows error on INVALID_CREDENTIALS", async () => {
    // ApiRequestError shape: { code, message, status }
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
});
