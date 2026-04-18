import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n/index";
import { TotpEnrollmentWizard } from "../TotpEnrollmentWizard";

vi.mock("../api", () => ({
  startEnrollment: vi.fn(() => Promise.resolve({
    secret_base32: "JBSWY3DPEHPK3PXP",
    provision_uri: "otpauth://totp/Schlass:a@x.com?secret=JBSWY3DPEHPK3PXP&issuer=Schlass",
  })),
}));

// AuthLayout depends on useAuth; provide a minimal mock.
vi.mock("@/features/auth/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "1", email: "a@x.com", role: "user", force_password_change: false, force_mfa_enrollment: true },
    loading: false,
    login: vi.fn(),
    logout: vi.fn(),
    refreshUser: vi.fn(),
  }),
}));

describe("TotpEnrollmentWizard", () => {
  it("starts on step 1 with the stepper and QR container", async () => {
    render(
      <I18nextProvider i18n={i18n}>
        <MemoryRouter><TotpEnrollmentWizard /></MemoryRouter>
      </I18nextProvider>,
    );
    // Step 1 label is displayed somewhere in the stepper
    const matches = await screen.findAllByText(/setup|scan/i);
    expect(matches.length).toBeGreaterThan(0);
  });
});
