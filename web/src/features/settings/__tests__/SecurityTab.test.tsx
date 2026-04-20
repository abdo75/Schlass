import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { SettingsPage } from "../SettingsPage";
import { getSettings, patchSecurity } from "../api";
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

describe("SettingsPage / Security tab end-to-end", () => {
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
      email: {
        smtp_host: "",
        smtp_port: 0,
        smtp_username: "",
        smtp_password_set: false,
        smtp_from: "",
      },
    });
    vi.mocked(patchSecurity).mockResolvedValue({
      mfa_required: true,
      password_min_length: 14,
      password_require_upper: true,
      password_require_digit: true,
      lockout_threshold: 5,
      lockout_duration_secs: 900,
    });
  });

  it("commits only the changed fields via patchSecurity", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());

    await userEvent.click(screen.getByRole("button", { name: "Security" }));

    // Bump minimum length from 12 to 14 by clicking Increase twice.
    await userEvent.click(screen.getByRole("button", { name: "Increase Minimum length" }));
    await userEvent.click(screen.getByRole("button", { name: "Increase Minimum length" }));

    // Save bar should show 1 unsaved change (only password_min_length dirty).
    expect(screen.getByText(/1 unsaved change/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(patchSecurity).toHaveBeenCalledWith({ password_min_length: 14 }),
    );
  });

  it("toggling a switch marks that field dirty and commits on Save", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Security" }));

    await userEvent.click(
      screen.getByRole("switch", { name: "Require uppercase letter" }),
    );
    expect(screen.getByText(/1 unsaved change/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(patchSecurity).toHaveBeenCalledWith({ password_require_upper: false }),
    );
  });

  it("converts Unlock duration from minutes to seconds in the PATCH", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Security" }));

    // default 900 sec = 15 min; bump to 16 min.
    await userEvent.click(
      screen.getByRole("button", { name: "Increase Unlock duration (minutes)" }),
    );

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(patchSecurity).toHaveBeenCalledWith({ lockout_duration_secs: 16 * 60 }),
    );
  });
});
