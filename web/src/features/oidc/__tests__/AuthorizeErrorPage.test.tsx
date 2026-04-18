import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n/index";
import { AuthorizeErrorPage } from "@/features/oidc/AuthorizeErrorPage";

// AuthLayout depends on useAuth; provide a minimal mock.
vi.mock("@/features/auth/AuthContext", () => ({
  useAuth: () => ({
    user: null,
    loading: false,
    login: vi.fn(),
    logout: vi.fn(),
    refreshUser: vi.fn(),
  }),
}));

function renderAt(url: string) {
  return render(
    <I18nextProvider i18n={i18n}>
      <MemoryRouter initialEntries={[url]}>
        <Routes>
          <Route path="/oidc/error" element={<AuthorizeErrorPage />} />
        </Routes>
      </MemoryRouter>
    </I18nextProvider>
  );
}

describe("AuthorizeErrorPage", () => {
  beforeEach(() => {
    // Mock clipboard.writeText. userEvent.setup() sets up its own clipboard
    // so we spyOn it after setup happens in the test itself.
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the reference from ?ref=", () => {
    renderAt("/oidc/error?ref=err_abcdef1234567890abcdef1234567890");
    expect(screen.getByTestId("oidc-error-ref")).toHaveTextContent(
      "err_abcdef1234567890abcdef1234567890"
    );
  });

  it("falls back to err_unknown when ?ref is missing", () => {
    renderAt("/oidc/error");
    expect(screen.getByTestId("oidc-error-ref")).toHaveTextContent(
      "err_unknown"
    );
  });

  it("renders the generic user-facing message regardless of ref", () => {
    renderAt("/oidc/error?ref=err_anything");
    // Title renders in English (default locale).
    expect(
      screen.getByText(/Sign-in couldn't be completed/i)
    ).toBeInTheDocument();
  });

  it("copies the ref to clipboard and toggles copied state", async () => {
    const user = userEvent.setup();
    renderAt("/oidc/error?ref=err_copyme1234567890abcdef1234567890");
    // Spy on clipboard.writeText after userEvent.setup() has initialized it
    const writeTextSpy = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    await user.click(screen.getByRole("button", { name: /copy/i }));
    expect(writeTextSpy).toHaveBeenCalledWith(
      "err_copyme1234567890abcdef1234567890"
    );
    // Eventually shows "Copied" label
    expect(screen.getByRole("button", { name: /copied/i })).toBeInTheDocument();
  });
});
