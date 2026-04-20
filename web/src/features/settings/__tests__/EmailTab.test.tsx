import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { SettingsPage } from "../SettingsPage";
import { getSettings, patchEmail, testEmailConnection } from "../api";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("../api", () => ({
  getSettings: vi.fn(),
  patchGeneral: vi.fn(),
  patchSecurity: vi.fn(),
  patchTokens: vi.fn(),
  patchEmail: vi.fn(),
  testEmailConnection: vi.fn(),
}));
vi.mock("@/features/auth/api");

function wrap() {
  return (
    <MemoryRouter>
      <AuthProvider>
        <SettingsPage />
      </AuthProvider>
    </MemoryRouter>
  );
}

const snapshotWithPassword = {
  general: { instance_name: "Acme" },
  security: {
    mfa_required: true,
    password_min_length: 12,
    password_require_upper: true,
    password_require_digit: true,
    lockout_threshold: 5,
    lockout_duration_secs: 900,
  },
  tokens: { access_token_ttl_secs: 900, refresh_token_ttl_secs: 86400 },
  email: {
    smtp_host: "smtp.example.com",
    smtp_port: 587,
    smtp_username: "u",
    smtp_password_set: true,
    smtp_from: "no-reply@example.com",
  },
};

const snapshotWithoutPassword = {
  ...snapshotWithPassword,
  email: { ...snapshotWithPassword.email, smtp_password_set: false },
};

describe("SettingsPage / Email tab end-to-end", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: {
        id: "u-0",
        email: "admin@example.com",
        role: "super_admin",
        force_password_change: false,
        force_mfa_enrollment: false,
      },
    });
    vi.mocked(getSettings).mockResolvedValue(snapshotWithPassword);
    vi.mocked(patchEmail).mockResolvedValue({
      smtp_host: "smtp.example.com",
      smtp_port: 587,
      smtp_username: "u",
      smtp_password_set: true,
      smtp_from: "new@example.com",
    });
  });

  it("renders 16-bullet password placeholder when password is set", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Email" }));
    const pw = screen.getByLabelText<HTMLInputElement>("Password");
    expect(pw.value).toBe("xxxxxxxxxxxxxxxx");
  });

  it("renders empty password field when no password is set", async () => {
    vi.mocked(getSettings).mockResolvedValue(snapshotWithoutPassword);
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Email" }));
    const pw = screen.getByLabelText<HTMLInputElement>("Password");
    expect(pw.value).toBe("");
  });

  it("omits smtp_password from PATCH when user didn't type into the password field", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Email" }));

    // Change only the From address.
    const from = screen.getByLabelText("From address");
    await userEvent.clear(from);
    await userEvent.type(from, "new@example.com");

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(patchEmail).toHaveBeenCalled());
    const body = vi.mocked(patchEmail).mock.calls[0][0];
    expect(body).toEqual({ smtp_from: "new@example.com" });
    expect(body).not.toHaveProperty("smtp_password");
  });

  it("includes smtp_password when user typed a new value", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Email" }));

    const pw = screen.getByLabelText("Password");
    // In a real browser, clicking the placeholder field auto-selects its
    // contents (onFocus/select()) and the first keystroke replaces the
    // selection — so the admin types "new-secret" and the controlled
    // value is exactly that. userEvent.type in JSDOM does not reliably
    // replace the selected text, so we simulate the end-state directly
    // with fireEvent.change: a new value lands in onChange, which mirrors
    // what the browser dispatches after selection-replacement.
    fireEvent.change(pw, { target: { value: "new-secret" } });

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(patchEmail).toHaveBeenCalled());
    const body = vi.mocked(patchEmail).mock.calls[0][0];
    expect(body).toHaveProperty("smtp_password", "new-secret");
  });

  it("disables Test connection while dirty", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Email" }));

    // Dirty the From field.
    const from = screen.getByLabelText("From address");
    await userEvent.clear(from);
    await userEvent.type(from, "new@example.com");

    const testBtn = screen.getByRole("button", { name: /test connection/i });
    expect(testBtn).toBeDisabled();
    expect(testBtn).toHaveAttribute("title", "Save before testing");
  });

  it("calls testEmailConnection when clean", async () => {
    vi.mocked(testEmailConnection).mockResolvedValue({
      delivered_at: "2026-04-20T12:00:00Z",
    });
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Email" }));

    await userEvent.click(screen.getByRole("button", { name: /test connection/i }));
    await waitFor(() => expect(testEmailConnection).toHaveBeenCalled());
    expect(await screen.findByText(/Delivered at/)).toBeInTheDocument();
  });
});
