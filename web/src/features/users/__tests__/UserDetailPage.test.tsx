import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { UserDetailPage } from "../UserDetailPage";
import * as usersApi from "../api";

vi.mock("../api");

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual =
    await vi.importActual<typeof import("react-router-dom")>(
      "react-router-dom",
    );
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

type DetailResponse = Awaited<ReturnType<typeof usersApi.getUser>>;

function makeDetail(
  overrides: Partial<DetailResponse["user"]> = {},
  sessions: DetailResponse["sessions"] = [],
): DetailResponse {
  const base = {
    id: "user-1",
    email: "target@example.com",
    role: "user",
    force_password_change: false,
    status: "active",
    created_at: "2026-04-14T12:00:00Z",
  };
  return {
    user: { ...base, ...overrides } as DetailResponse["user"],
    sessions,
  };
}

function renderPage(id = "user-1") {
  return render(
    <MemoryRouter initialEntries={[`/admin/users/${id}`]}>
      <Routes>
        <Route path="/admin/users/:id" element={<UserDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("UserDetailPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
  });

  it("loads and renders user data on mount", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({ email: "alice@example.com", role: "super_admin" }),
    );
    renderPage();

    expect(
      await screen.findByRole("heading", { name: "alice@example.com" }),
    ).toBeInTheDocument();
    expect(usersApi.getUser).toHaveBeenCalledWith("user-1");
  });

  it("edit mode save calls updateUser and refetches", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({ email: "old@example.com", role: "user" }),
    );
    vi.mocked(usersApi.updateUser).mockResolvedValue({
      user: {
        id: "user-1",
        email: "new@example.com",
        role: "super_admin",
        force_password_change: false,
      },
    });

    renderPage();
    const user = userEvent.setup();

    await screen.findByRole("heading", { name: "old@example.com" });
    await user.click(screen.getByRole("button", { name: /^edit$/i }));

    const emailInput = screen.getByLabelText(/email/i);
    await user.clear(emailInput);
    await user.type(emailInput, "new@example.com");
    await user.selectOptions(screen.getByLabelText(/role/i), "super_admin");
    await user.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => {
      expect(usersApi.updateUser).toHaveBeenCalledWith("user-1", {
        email: "new@example.com",
        role: "super_admin",
      });
    });
    // Refetched after save
    await waitFor(() => {
      expect(usersApi.getUser).toHaveBeenCalledTimes(2);
    });
  });

  it("disable button opens confirm, confirm calls disableUser and refetches", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(makeDetail());
    vi.mocked(usersApi.disableUser).mockResolvedValue();

    renderPage();
    const user = userEvent.setup();
    await screen.findByRole("heading", { name: "target@example.com" });

    await user.click(screen.getByRole("button", { name: /disable user/i }));
    // Dialog renders
    const confirmBtn = await screen.findByRole("button", {
      name: /^disable$/i,
    });
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(usersApi.disableUser).toHaveBeenCalledWith("user-1");
    });
    await waitFor(() => {
      expect(usersApi.getUser).toHaveBeenCalledTimes(2);
    });
  });

  it("delete button opens confirm, confirm calls deleteUser and navigates", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(makeDetail());
    vi.mocked(usersApi.deleteUser).mockResolvedValue();

    renderPage();
    const user = userEvent.setup();
    await screen.findByRole("heading", { name: "target@example.com" });

    await user.click(screen.getByRole("button", { name: /delete user/i }));
    const confirmBtn = await screen.findByRole("button", {
      name: /delete permanently/i,
    });
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(usersApi.deleteUser).toHaveBeenCalledWith("user-1");
    });
    await waitFor(() => {
      expect(navigateMock).toHaveBeenCalledWith("/admin/users");
    });
  });

  it("reset password inline form calls resetUserPassword", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(makeDetail());
    vi.mocked(usersApi.resetUserPassword).mockResolvedValue();

    renderPage();
    const user = userEvent.setup();
    await screen.findByRole("heading", { name: "target@example.com" });

    await user.click(screen.getByRole("button", { name: /reset password/i }));
    await user.type(
      screen.getByLabelText(/new temporary password/i),
      "BrandNewPass123",
    );
    await user.click(screen.getByRole("button", { name: /set password/i }));

    await waitFor(() => {
      expect(usersApi.resetUserPassword).toHaveBeenCalledWith(
        "user-1",
        "BrandNewPass123",
      );
    });
  });

  it("renders sessions and per-session kill button calls terminateSession", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(
      makeDetail({}, [
        {
          token: "tok-aaa",
          created_at: "2026-04-14T10:00:00Z",
          last_seen_at: "2026-04-14T12:00:00Z",
          ip_address: "10.0.0.1",
          user_agent: "Mozilla/5.0 Firefox",
        },
      ]),
    );
    vi.mocked(usersApi.terminateSession).mockResolvedValue();

    renderPage();
    const user = userEvent.setup();
    const row = (await screen.findByText("10.0.0.1")).closest("tr");
    expect(row).not.toBeNull();

    await user.click(
      within(row as HTMLElement).getByRole("button", { name: /kill session/i }),
    );

    await waitFor(() => {
      expect(usersApi.terminateSession).toHaveBeenCalledWith(
        "user-1",
        "tok-aaa",
      );
    });
  });

  it("shows translated error on CANNOT_OPERATE_ON_SELF", async () => {
    vi.mocked(usersApi.getUser).mockResolvedValue(makeDetail());
    vi.mocked(usersApi.disableUser).mockRejectedValue({
      code: "CANNOT_OPERATE_ON_SELF",
      message: "nope",
      status: 403,
    });

    renderPage();
    const user = userEvent.setup();
    await screen.findByRole("heading", { name: "target@example.com" });

    await user.click(screen.getByRole("button", { name: /disable user/i }));
    const confirmBtn = await screen.findByRole("button", {
      name: /^disable$/i,
    });
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/your own account/i);
    });
  });
});
