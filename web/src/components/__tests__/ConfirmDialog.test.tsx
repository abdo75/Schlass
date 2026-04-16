import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@/i18n";
import { ConfirmDialog } from "../ConfirmDialog";

describe("ConfirmDialog", () => {
  it("renders nothing when open is false", () => {
    const { container } = render(
      <ConfirmDialog
        open={false}
        onOpenChange={() => {}}
        title="Disable bob?"
        body="They will be signed out."
        confirmLabel="Disable user"
        onConfirm={() => {}}
      />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders title, body, and confirm label when open", () => {
    render(
      <ConfirmDialog
        open
        onOpenChange={() => {}}
        title="Disable bob?"
        body="They will be signed out."
        confirmLabel="Disable user"
        onConfirm={() => {}}
      />,
    );
    expect(screen.getByText("Disable bob?")).toBeInTheDocument();
    expect(screen.getByText("They will be signed out.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /disable user/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();
  });

  it("calls onConfirm and closes when confirm button is clicked", async () => {
    const onConfirm = vi.fn();
    const onOpenChange = vi.fn();
    render(
      <ConfirmDialog
        open
        onOpenChange={onOpenChange}
        title="Disable bob?"
        body="Body"
        confirmLabel="Disable user"
        onConfirm={onConfirm}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /disable user/i }));
    expect(onConfirm).toHaveBeenCalled();
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("calls onOpenChange(false) when Cancel is clicked", async () => {
    const onOpenChange = vi.fn();
    render(
      <ConfirmDialog
        open
        onOpenChange={onOpenChange}
        title="Title"
        body="Body"
        confirmLabel="Confirm"
        onConfirm={() => {}}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("closes on Escape key", async () => {
    const onOpenChange = vi.fn();
    render(
      <ConfirmDialog
        open
        onOpenChange={onOpenChange}
        title="Title"
        body="Body"
        confirmLabel="Confirm"
        onConfirm={() => {}}
      />,
    );
    const user = userEvent.setup();
    await user.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
