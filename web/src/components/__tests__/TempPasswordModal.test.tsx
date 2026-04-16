import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@/i18n";
import { TempPasswordModal } from "../TempPasswordModal";

describe("TempPasswordModal", () => {
  it("renders the password, the email, and the one-shot warning", () => {
    render(
      <TempPasswordModal
        email="bob@test.local"
        password="K7mR3pL9vX2qT8wN"
        onClose={() => {}}
      />,
    );
    expect(screen.getByText("K7mR3pL9vX2qT8wN")).toBeInTheDocument();
    expect(screen.getByText(/bob@test.local/)).toBeInTheDocument();
    expect(screen.getByText(/shown once/i)).toBeInTheDocument();
  });

  it("copies the password to clipboard on Copy click", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    render(
      <TempPasswordModal
        email="bob@test.local"
        password="K7mR3pL9vX2qT8wN"
        onClose={() => {}}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /copy/i }));
    expect(writeText).toHaveBeenCalledWith("K7mR3pL9vX2qT8wN");
  });

  it("does not call onClose when Escape is pressed", async () => {
    const onClose = vi.fn();
    render(
      <TempPasswordModal
        email="bob@test.local"
        password="K7mR3pL9vX2qT8wN"
        onClose={onClose}
      />,
    );
    const user = userEvent.setup();
    await user.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
  });

  it("calls onClose when Done is clicked", async () => {
    const onClose = vi.fn();
    render(
      <TempPasswordModal
        email="bob@test.local"
        password="K7mR3pL9vX2qT8wN"
        onClose={onClose}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /done/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
