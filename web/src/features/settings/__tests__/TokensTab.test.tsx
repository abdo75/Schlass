import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { SettingsPage } from "../SettingsPage";
import { getSettings, patchTokens } from "../api";
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

describe("SettingsPage / Tokens tab end-to-end", () => {
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
    vi.mocked(patchTokens).mockResolvedValue({
      access_token_ttl_secs: 1200,
      refresh_token_ttl_secs: 86400,
    });
  });

  it("converts minutes→seconds on Save for access token", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Tokens" }));

    // Default 900s = 15min; bump to 20min via 5 clicks on Increase.
    for (let i = 0; i < 5; i++) {
      await userEvent.click(
        screen.getByRole("button", { name: "Increase Access token lifetime (minutes)" }),
      );
    }
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(patchTokens).toHaveBeenCalledWith({ access_token_ttl_secs: 20 * 60 }),
    );
  });

  it("converts hours→seconds on Save for refresh token", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "Tokens" }));

    // Default 86400s = 24h; bump to 25h.
    await userEvent.click(
      screen.getByRole("button", { name: "Increase Refresh token lifetime (hours)" }),
    );
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(patchTokens).toHaveBeenCalledWith({ refresh_token_ttl_secs: 25 * 3600 }),
    );
  });
});
