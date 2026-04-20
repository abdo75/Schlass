import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import "@/i18n";
import { SettingsPage } from "../SettingsPage";
import { getSettings, patchGeneral } from "../api";
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

describe("SettingsPage / General tab end-to-end", () => {
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
      general: { instance_name: "Old" },
      security: {
        mfa_required: true,
        password_min_length: 12,
        password_require_upper: true,
        password_require_digit: true,
        lockout_threshold: 5,
        lockout_duration_secs: 900,
      },
      tokens: { access_token_ttl_secs: 900, refresh_token_ttl_secs: 86400 },
      email: { smtp_host: "", smtp_port: 0, smtp_username: "", smtp_password_set: false, smtp_from: "" },
    });
    vi.mocked(patchGeneral).mockResolvedValue({ instance_name: "New" });
  });

  it("shows floating save bar when Instance name is dirty and commits via patchGeneral on Save", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());

    const input = screen.getByLabelText(/Instance name/);
    await userEvent.clear(input);
    await userEvent.type(input, "New");

    expect(screen.getByText(/unsaved change/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(patchGeneral).toHaveBeenCalledWith({ instance_name: "New" }));
  });

  it("Discard clears the buffer and hides the save bar", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());

    const input = screen.getByLabelText(/Instance name/);
    await userEvent.clear(input);
    await userEvent.type(input, "Dirty");
    expect(screen.getByText(/unsaved change/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /discard/i }));
    expect(screen.queryByText(/unsaved change/)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/Instance name/)).toHaveValue("Old");
  });

  it("does NOT render floating save bar when clean", async () => {
    render(wrap());
    await waitFor(() => expect(getSettings).toHaveBeenCalled());
    expect(screen.queryByText(/unsaved change/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^save$/i })).not.toBeInTheDocument();
  });
});
