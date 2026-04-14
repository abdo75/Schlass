import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { AuthGuard } from "../AuthGuard";
import * as authApi from "@/features/auth/api";
import { AuthProvider } from "@/features/auth/AuthContext";

vi.mock("@/features/auth/api");

describe("AuthGuard", () => {
  it("renders children when authenticated", async () => {
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: { id: "1", email: "a@b.co", role: "super_admin", force_password_change: false },
    });
    render(
      <MemoryRouter initialEntries={["/admin"]}>
        <AuthProvider>
          <Routes>
            <Route path="/admin" element={<AuthGuard><div>secret</div></AuthGuard>} />
            <Route path="/login" element={<div>login page</div>} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("secret")).toBeInTheDocument());
  });

  it("redirects to /login when not authenticated", async () => {
    vi.mocked(authApi.getMe).mockRejectedValue(new Error("unauthorized"));
    render(
      <MemoryRouter initialEntries={["/admin"]}>
        <AuthProvider>
          <Routes>
            <Route path="/admin" element={<AuthGuard><div>secret</div></AuthGuard>} />
            <Route path="/login" element={<div>login page</div>} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("login page")).toBeInTheDocument());
  });
});
