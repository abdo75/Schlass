import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AuditPanel } from "./AuditPanel";
import { fakeEvent } from "./test-helpers";

describe("AuditPanel", () => {
  it("renders hero with outcome chip and sentence", () => {
    render(<AuditPanel event={fakeEvent({ event_type: "login.succeeded", outcome: "success" })} onClose={vi.fn()} />);
    expect(screen.getByText(/success/i)).toBeVisible();
    expect(screen.getByText(/signed in/i)).toBeVisible();
  });

  it("renders Critical badge for refresh-token reuse", () => {
    render(<AuditPanel event={fakeEvent({ event_type: "oidc.refresh.reuse_detected", outcome: "failure" })} onClose={vi.fn()} />);
    expect(screen.getByText(/critical/i)).toBeVisible();
  });

  it("closes when the backdrop is clicked", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<AuditPanel event={fakeEvent()} onClose={onClose} />);

    await user.click(screen.getByTestId("audit-panel-backdrop"));

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does not close when the panel itself is clicked", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<AuditPanel event={fakeEvent()} onClose={onClose} />);

    await user.click(screen.getByRole("dialog", { name: /event detail/i }));

    expect(onClose).not.toHaveBeenCalled();
  });

  it("closes when Escape is pressed", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<AuditPanel event={fakeEvent()} onClose={onClose} />);

    await user.keyboard("{Escape}");

    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
