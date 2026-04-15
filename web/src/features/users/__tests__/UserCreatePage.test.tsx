import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { UserCreatePage } from "../UserCreatePage";
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

function renderPage() {
  return render(
    <MemoryRouter>
      <UserCreatePage />
    </MemoryRouter>,
  );
}

describe("UserCreatePage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
  });

  it("renders the form fields", () => {
    renderPage();
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/temporary password/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/role/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /create user/i }),
    ).toBeInTheDocument();
  });

  it("submits the form and navigates to the new user's detail", async () => {
    vi.mocked(usersApi.createUser).mockResolvedValue({
      user: {
        id: "new-user-123",
        email: "new@example.com",
        role: "user",
        force_password_change: true,
      },
      temporary_password: "TempPass123",
    });

    renderPage();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText(/email/i), "new@example.com");
    await user.type(
      screen.getByLabelText(/temporary password/i),
      "SuperSecret1234",
    );
    await user.selectOptions(screen.getByLabelText(/role/i), "super_admin");
    await user.click(screen.getByRole("button", { name: /create user/i }));

    await waitFor(() => {
      expect(usersApi.createUser).toHaveBeenCalledWith(
        "new@example.com",
        "super_admin",
      );
    });
    await waitFor(() => {
      expect(navigateMock).toHaveBeenCalledWith("/admin/users/new-user-123");
    });
  });

  it("shows a translated error when EMAIL_ALREADY_EXISTS", async () => {
    vi.mocked(usersApi.createUser).mockRejectedValue({
      code: "EMAIL_ALREADY_EXISTS",
      message: "duplicate",
      status: 409,
    });

    renderPage();
    const user = userEvent.setup();

    await user.type(screen.getByLabelText(/email/i), "dup@example.com");
    await user.type(
      screen.getByLabelText(/temporary password/i),
      "SuperSecret1234",
    );
    await user.click(screen.getByRole("button", { name: /create user/i }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/already exists/i);
    });
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("cancel button navigates back to /admin/users", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(navigateMock).toHaveBeenCalledWith("/admin/users");
  });
});
