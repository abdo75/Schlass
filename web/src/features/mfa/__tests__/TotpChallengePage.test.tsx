import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n";
import { TotpChallengePage } from "../TotpChallengePage";

const submitMock = vi.fn();
vi.mock("../api", () => ({
  submitChallenge: (input: unknown) => submitMock(input) as unknown,
}));

const refreshUserMock = vi.fn();
vi.mock("@/features/auth/AuthContext", () => ({
  useAuth: () => ({
    user: null,
    loading: false,
    login: vi.fn(),
    logout: vi.fn(),
    refreshUser: refreshUserMock,
  }),
}));

describe("TotpChallengePage", () => {
  beforeEach(() => {
    submitMock.mockReset();
    refreshUserMock.mockReset();
  });

  it("renders 6 digit boxes in TOTP mode", () => {
    render(
      <I18nextProvider i18n={i18n}>
        <MemoryRouter>
          <TotpChallengePage />
        </MemoryRouter>
      </I18nextProvider>,
    );
    expect(screen.getAllByLabelText(/digit/i)).toHaveLength(6);
  });

  it("toggles to recovery-code mode when the link is clicked", () => {
    render(
      <I18nextProvider i18n={i18n}>
        <MemoryRouter>
          <TotpChallengePage />
        </MemoryRouter>
      </I18nextProvider>,
    );
    fireEvent.click(screen.getByText(/recovery code/i));
    expect(screen.getByPlaceholderText("XXXX-XXXX")).toBeInTheDocument();
  });

  it("submits TOTP code and calls refreshUser on success", async () => {
    submitMock.mockResolvedValue({});
    refreshUserMock.mockResolvedValue({
      id: "1",
      email: "a@x.com",
      role: "user",
      force_password_change: false,
      force_mfa_enrollment: false,
    });
    render(
      <I18nextProvider i18n={i18n}>
        <MemoryRouter>
          <TotpChallengePage />
        </MemoryRouter>
      </I18nextProvider>,
    );
    const inputs = screen.getAllByLabelText(/digit/i);
    "123456".split("").forEach((d, i) => fireEvent.change(inputs[i], { target: { value: d } }));
    fireEvent.click(screen.getByRole("button", { name: /verify/i }));
    await waitFor(() => expect(submitMock).toHaveBeenCalledWith({ code: "123456" }));
    expect(refreshUserMock).toHaveBeenCalled();
  });
});
