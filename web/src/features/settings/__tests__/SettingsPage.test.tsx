import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { SettingsPage } from "../SettingsPage";
import { getSettings } from "../api";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

vi.mock("../api", () => ({
  getSettings: vi.fn(),
  patchGeneral: vi.fn(),
  patchSecurity: vi.fn(),
  patchTokens: vi.fn(),
  patchAuditLog: vi.fn(),
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

describe("SettingsPage shell", () => {
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
    vi.mocked(getSettings).mockResolvedValue({
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
      audit_log: { audit_view_logging_enabled: true, audit_export_max_rows: 50000 },
      email: { smtp_host: "", smtp_port: 0, smtp_username: "", smtp_password_set: false, smtp_from: "" },
    });
  });

  it("loads snapshot on mount and renders settings tabs", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    expect(screen.getByRole("button", { name: "General" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Security" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Tokens" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Audit log" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Email" })).toBeInTheDocument();
  });

  it("switches active tab on click", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Email" }));
    expect(screen.getByRole("heading", { name: "SMTP server" })).toBeInTheDocument();
  });
});
