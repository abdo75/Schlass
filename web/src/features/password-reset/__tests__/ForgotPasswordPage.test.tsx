import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ForgotPasswordPage } from "../ForgotPasswordPage";
import { requestPasswordReset } from "../api";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("../api", () => ({
  requestPasswordReset: vi.fn(),
  confirmPasswordReset: vi.fn(),
}));

vi.mock("@/features/auth/api");

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ForgotPasswordPage />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("ForgotPasswordPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(requestPasswordReset).mockResolvedValue(undefined);
    // AuthProvider's getMe call on mount — reject so the context settles to "not authed".
    vi.mocked(authApi.getMe).mockRejectedValue(new Error("unauthorized"));
  });

  it("posts to request endpoint on submit and shows success state with the entered email", async () => {
    renderPage();
    await userEvent.type(screen.getByLabelText(/email/i), "alice@example.com");
    await userEvent.click(screen.getByRole("button", { name: /send reset link/i }));
    await waitFor(() => expect(requestPasswordReset).toHaveBeenCalledWith("alice@example.com"));
    expect(await screen.findByText(/Check your email/)).toBeInTheDocument();
    expect(screen.getByText(/alice@example.com/)).toBeInTheDocument();
  });

  it("shows success state even on API error (enumeration-safe UI)", async () => {
    vi.mocked(requestPasswordReset).mockRejectedValue(new Error("network"));
    renderPage();
    await userEvent.type(screen.getByLabelText(/email/i), "bob@example.com");
    await userEvent.click(screen.getByRole("button", { name: /send reset link/i }));
    expect(await screen.findByText(/Check your email/)).toBeInTheDocument();
    expect(screen.getByText(/bob@example.com/)).toBeInTheDocument();
  });

  it("Back to sign in link points at /login", () => {
    renderPage();
    const link = screen.getByRole("link", { name: /Back to sign in/i });
    expect(link).toHaveAttribute("href", "/login");
  });

  it("shows the admin-cannot-reset-by-email banner", () => {
    renderPage();
    expect(
      screen.getByText(/Administrator accounts can't reset by email/i),
    ).toBeInTheDocument();
  });

  it("shows the single-admin recovery prompt + guide link", () => {
    renderPage();
    expect(
      screen.getByText(/Single-admin instance with no backup/i),
    ).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /Operator recovery guide/i });
    expect(link).toHaveAttribute(
      "href",
      "https://github.com/abdo75/Schlass/blob/main/docs/operator/recovery.md",
    );
  });
});
