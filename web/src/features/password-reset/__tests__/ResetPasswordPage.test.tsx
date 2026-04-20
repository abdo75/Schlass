import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ResetPasswordPage } from "../ResetPasswordPage";
import { confirmPasswordReset, validateResetToken } from "../api";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("../api", () => ({
  requestPasswordReset: vi.fn(),
  confirmPasswordReset: vi.fn(),
  validateResetToken: vi.fn(),
}));

vi.mock("@/features/auth/api");

function renderWithToken(token: string) {
  return render(
    <MemoryRouter initialEntries={[`/reset-password/${token}`]}>
      <AuthProvider>
        <Routes>
          <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("ResetPasswordPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // AuthProvider's getMe call on mount — reject so the context settles to "not authed".
    vi.mocked(authApi.getMe).mockRejectedValue(new Error("unauthorized"));
    // validateResetToken: always resolve so the form renders in these tests.
    vi.mocked(validateResetToken).mockResolvedValue({});
  });

  it("submits new password and shows success state on 200", async () => {
    vi.mocked(confirmPasswordReset).mockResolvedValue({ user_id: "u-1" });
    renderWithToken("validtoken");

    // Wait for mount-time validation to complete before the form appears.
    await userEvent.type(await screen.findByLabelText(/^new password$/i), "NewStrongPass1!");
    await userEvent.type(screen.getByLabelText(/confirm new password/i), "NewStrongPass1!");
    await userEvent.click(screen.getByRole("button", { name: /reset password/i }));

    await waitFor(() =>
      expect(confirmPasswordReset).toHaveBeenCalledWith("validtoken", "NewStrongPass1!"),
    );
    expect(await screen.findByText(/Password reset$/)).toBeInTheDocument();
  });

  it("renders invalid state on INVALID_TOKEN", async () => {
    const err = Object.assign(new Error("invalid"), { code: "INVALID_TOKEN" });
    vi.mocked(confirmPasswordReset).mockRejectedValue(err);
    renderWithToken("badtoken");

    // Wait for mount-time validation to complete before the form appears.
    await userEvent.type(await screen.findByLabelText(/^new password$/i), "NewStrongPass1!");
    await userEvent.type(screen.getByLabelText(/confirm new password/i), "NewStrongPass1!");
    await userEvent.click(screen.getByRole("button", { name: /reset password/i }));

    expect(await screen.findByText(/no longer valid/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /request a new link/i })).toBeInTheDocument();
  });

  it("shows PASSWORD_MISMATCH inline when confirm doesn't match", async () => {
    renderWithToken("validtoken");
    // Wait for mount-time validation to complete before the form appears.
    await userEvent.type(await screen.findByLabelText(/^new password$/i), "AAAA");
    await userEvent.type(screen.getByLabelText(/confirm new password/i), "BBBB");
    await userEvent.click(screen.getByRole("button", { name: /reset password/i }));
    expect(await screen.findByText(/Passwords don't match/)).toBeInTheDocument();
    expect(confirmPasswordReset).not.toHaveBeenCalled();
  });

  it("shows PASSWORD_POLICY_VIOLATION when backend rejects", async () => {
    const err = Object.assign(new Error("weak"), { code: "PASSWORD_POLICY_VIOLATION" });
    vi.mocked(confirmPasswordReset).mockRejectedValue(err);
    renderWithToken("validtoken");
    // Wait for mount-time validation to complete before the form appears.
    await userEvent.type(await screen.findByLabelText(/^new password$/i), "short");
    await userEvent.type(screen.getByLabelText(/confirm new password/i), "short");
    await userEvent.click(screen.getByRole("button", { name: /reset password/i }));
    expect(await screen.findByText(/does not meet the policy/i)).toBeInTheDocument();
  });
});

describe("ResetPasswordPage — password autocomplete", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(authApi.getMe).mockRejectedValue(new Error("unauthorized"));
    // validateResetToken: always resolve so the form renders in these tests.
    vi.mocked(validateResetToken).mockResolvedValue({});
  });

  it("marks new-password fields with autocomplete='new-password'", async () => {
    render(
      <MemoryRouter initialEntries={["/reset-password/some-token"]}>
        <AuthProvider>
          <Routes>
            <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    );
    const inputs = await screen.findAllByLabelText(/new password|confirm new password/i);
    expect(inputs).toHaveLength(2);
    inputs.forEach((el) => expect(el).toHaveAttribute("autocomplete", "new-password"));
  });
});
