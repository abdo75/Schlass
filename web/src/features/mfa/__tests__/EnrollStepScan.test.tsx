import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n";
import { EnrollStepScan } from "../EnrollStepScan";
import type { Mock } from "vitest";

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const startMock = vi.fn((): Promise<unknown> => Promise.resolve(null));
vi.mock("../api", () => ({
  startEnrollment: () => startMock(),
}));

const useAuthMock = vi.fn((): { user: { role: string } | null } => ({ user: null }));
vi.mock("@/features/auth/AuthContext", () => ({
  useAuth: () => useAuthMock(),
}));

describe("EnrollStepScan redirect codes", () => {
  beforeEach(() => {
    navigateMock.mockReset();
    (startMock as Mock).mockReset();
    (useAuthMock as Mock).mockReset();
  });

  it("unauthenticated + expired → /login", async () => {
    (startMock as Mock).mockRejectedValue({ code: "MFA_ENROLLMENT_EXPIRED" });
    (useAuthMock as Mock).mockReturnValue({ user: null });
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepScan onNext={() => {}} />
      </I18nextProvider>,
    );
    await vi.waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/login", { replace: true }));
  });

  it("super_admin + expired → /admin", async () => {
    (startMock as Mock).mockRejectedValue({ code: "MFA_ENROLLMENT_EXPIRED" });
    (useAuthMock as Mock).mockReturnValue({ user: { role: "super_admin" } });
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepScan onNext={() => {}} />
      </I18nextProvider>,
    );
    await vi.waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/admin", { replace: true }));
  });

  it("role=user + expired → /account", async () => {
    (startMock as Mock).mockRejectedValue({ code: "MFA_ENROLLMENT_EXPIRED" });
    (useAuthMock as Mock).mockReturnValue({ user: { role: "user" } });
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepScan onNext={() => {}} />
      </I18nextProvider>,
    );
    await vi.waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/account", { replace: true }));
  });

  it("super_admin + already enrolled → /admin", async () => {
    (startMock as Mock).mockRejectedValue({ code: "MFA_ALREADY_ENROLLED" });
    (useAuthMock as Mock).mockReturnValue({ user: { role: "super_admin" } });
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepScan onNext={() => {}} />
      </I18nextProvider>,
    );
    await vi.waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/admin", { replace: true }));
  });

  it("role=user + already enrolled → /account", async () => {
    (startMock as Mock).mockRejectedValue({ code: "MFA_ALREADY_ENROLLED" });
    (useAuthMock as Mock).mockReturnValue({ user: { role: "user" } });
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepScan onNext={() => {}} />
      </I18nextProvider>,
    );
    await vi.waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/account", { replace: true }));
  });

  it("other error codes still surface inline", async () => {
    (startMock as Mock).mockRejectedValue({ code: "INTERNAL_ERROR" });
    (useAuthMock as Mock).mockReturnValue({ user: null });
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepScan onNext={() => {}} />
      </I18nextProvider>,
    );
    await vi.waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(navigateMock).not.toHaveBeenCalled();
  });
});
