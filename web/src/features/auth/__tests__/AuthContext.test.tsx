import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import { AuthProvider, useAuth } from "../AuthContext";
import * as authApi from "../api";

vi.mock("../api");

function Probe() {
  const { user, loading } = useAuth();
  if (loading) return <div>loading</div>;
  return <div>{user ? user.email : "anonymous"}</div>;
}

describe("AuthContext", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows loading then user", async () => {
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: { id: "1", email: "a@b.co", role: "super_admin", force_password_change: false, force_mfa_enrollment: false },
    });
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    expect(screen.getByText("loading")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("a@b.co")).toBeInTheDocument());
  });

  it("shows anonymous when getMe 401s", async () => {
    vi.mocked(authApi.getMe).mockRejectedValue(new Error("unauthorized"));
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("anonymous")).toBeInTheDocument());
  });

  it("clears user on schlass:unauthorized event", async () => {
    vi.mocked(authApi.getMe).mockResolvedValue({
      user: { id: "1", email: "a@b.co", role: "super_admin", force_password_change: false, force_mfa_enrollment: false },
    });
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("a@b.co")).toBeInTheDocument());

    act(() => {
      window.dispatchEvent(new CustomEvent("schlass:unauthorized"));
    });
    await waitFor(() => expect(screen.getByText("anonymous")).toBeInTheDocument());
  });
});
