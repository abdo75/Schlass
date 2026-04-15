import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { UsersPage } from "../UsersPage";
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

type ListResponse = Awaited<ReturnType<typeof usersApi.listUsers>>;

function makeUser(i: number, overrides: Partial<ListResponse["users"][number]> = {}) {
  return {
    id: `id-${i}`,
    email: `user${i}@example.com`,
    role: "user",
    force_password_change: false,
    status: "active",
    created_at: "2026-04-14T12:00:00Z",
    ...overrides,
    // carry the extra props through the loose AuthUser type
  } as ListResponse["users"][number];
}

function makeResponse(total: number, users: ListResponse["users"]): ListResponse {
  return { users, total, limit: 25, offset: 0 };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <UsersPage />
    </MemoryRouter>,
  );
}

describe("UsersPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
  });

  it("renders a list of users fetched from the API", async () => {
    vi.mocked(usersApi.listUsers).mockResolvedValue(
      makeResponse(2, [
        makeUser(1, { email: "alice@example.com", role: "super_admin" }),
        makeUser(2, { email: "bob@example.com" }),
      ]),
    );
    renderPage();

    expect(await screen.findByText("alice@example.com")).toBeInTheDocument();
    expect(screen.getByText("bob@example.com")).toBeInTheDocument();
    expect(usersApi.listUsers).toHaveBeenCalledWith(25, 0, undefined);
  });

  it("filters by email on search input change", async () => {
    vi.mocked(usersApi.listUsers).mockResolvedValue(
      makeResponse(1, [makeUser(1, { email: "alice@example.com" })]),
    );
    renderPage();
    await screen.findByText("alice@example.com");

    const user = userEvent.setup();
    await user.type(
      screen.getByPlaceholderText(/search by email/i),
      "ali",
    );

    await waitFor(() => {
      expect(usersApi.listUsers).toHaveBeenLastCalledWith(25, 0, "ali");
    });
  });

  it("pagination buttons advance and retreat offset", async () => {
    // total=60, PAGE_SIZE=25 → 3 pages
    vi.mocked(usersApi.listUsers).mockResolvedValue(
      makeResponse(60, [makeUser(1)]),
    );
    renderPage();
    await screen.findByText("user1@example.com");

    const user = userEvent.setup();
    const nextBtn = screen.getByRole("button", { name: /next page/i });
    const prevBtn = screen.getByRole("button", { name: /previous page/i });

    expect(prevBtn).toBeDisabled();
    expect(nextBtn).toBeEnabled();

    await user.click(nextBtn);
    await waitFor(() => {
      expect(usersApi.listUsers).toHaveBeenLastCalledWith(25, 25, undefined);
    });

    await user.click(prevBtn);
    await waitFor(() => {
      expect(usersApi.listUsers).toHaveBeenLastCalledWith(25, 0, undefined);
    });
  });

  it("row click navigates to the user detail page", async () => {
    vi.mocked(usersApi.listUsers).mockResolvedValue(
      makeResponse(1, [makeUser(42, { id: "user-42" })]),
    );
    renderPage();
    const row = (await screen.findByText("user42@example.com")).closest("tr");
    expect(row).not.toBeNull();

    const user = userEvent.setup();
    await user.click(within(row as HTMLElement).getByText("user42@example.com"));

    expect(navigateMock).toHaveBeenCalledWith("/admin/users/user-42");
  });

  it("shows a translated error on API failure", async () => {
    vi.mocked(usersApi.listUsers).mockRejectedValue({
      code: "INTERNAL_ERROR",
      message: "boom",
      status: 500,
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        /unexpected error/i,
      );
    });
  });
});
