import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ResetPasswordPage } from "../ResetPasswordPage";
import { AuthProvider } from "@/features/auth/AuthContext";
import * as authApi from "@/features/auth/api";

// Only getMe is mocked; validateResetToken / confirmPasswordReset go through
// real apiFetch so fetchMock captures the outbound HTTP call under test.
vi.mock("@/features/auth/api", async () => {
  const actual = await vi.importActual<typeof import("@/features/auth/api")>(
    "@/features/auth/api",
  );
  return { ...actual, getMe: vi.fn() };
});

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  // AuthProvider's getMe call on mount — reject so the context settles to "not authed".
  vi.mocked(authApi.getMe).mockRejectedValue(new Error("unauthorized"));
});
afterEach(() => {
  vi.unstubAllGlobals();
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("ResetPasswordPage — mount-time validation", () => {
  it("shows loading state until /validate resolves", () => {
    fetchMock.mockImplementation(() => new Promise(() => {}));
    renderAt("/reset-password/tok");
    expect(screen.getByRole("status")).toHaveTextContent(/checking/i);
    expect(screen.queryAllByLabelText(/new password/i)).toHaveLength(0);
  });

  it("renders the form after a 200 response", async () => {
    fetchMock.mockResolvedValue(
      new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    );
    renderAt("/reset-password/tok");
    const inputs = await screen.findAllByLabelText(/new password/i);
    expect(inputs.length).toBeGreaterThanOrEqual(1);
  });

  it("renders the invalid-link card on 400 INVALID_TOKEN", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: "INVALID_TOKEN", message: "bad" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      }),
    );
    renderAt("/reset-password/tok");
    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 4 })).toHaveTextContent(/no longer valid/i),
    );
    expect(screen.queryAllByLabelText(/new password/i)).toHaveLength(0);
  });

  it("calls /validate exactly once on mount with the URL token", async () => {
    fetchMock.mockResolvedValue(
      new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    );
    renderAt("/reset-password/url-token");
    await screen.findAllByLabelText(/new password/i);
    const validateCalls = fetchMock.mock.calls.filter(([u]) =>
      String(u).endsWith("/api/password-reset/validate"),
    );
    expect(validateCalls).toHaveLength(1);
    const options = validateCalls[0][1] as RequestInit;
    const body = JSON.parse(options.body as string) as { token: string };
    expect(body.token).toBe("url-token");
  });
});
