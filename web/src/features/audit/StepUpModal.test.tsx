import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { StepUpModal } from "./StepUpModal";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("StepUpModal", () => {
  it("auto-focuses the code input on open", () => {
    render(<StepUpModal open onCancel={vi.fn()} onVerified={vi.fn()} />);
    expect(screen.getByLabelText(/Authenticator code/i)).toHaveFocus();
  });

  it("closes on Escape", () => {
    const onCancel = vi.fn();
    render(<StepUpModal open onCancel={onCancel} onVerified={vi.fn()} />);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onCancel).toHaveBeenCalled();
  });

  it("submits a TOTP code and calls onVerified", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    const onVerified = vi.fn();
    render(<StepUpModal open onCancel={vi.fn()} onVerified={onVerified} />);

    fireEvent.change(screen.getByLabelText(/Authenticator code/i), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(onVerified).toHaveBeenCalled());
    expect(fetch).toHaveBeenCalledWith("/api/auth/stepup/challenge", expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ code: "123456" }),
    }));
  });

  it("shows backend errors and supports cancel", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ error: "MFA_INVALID_CODE", message: "Invalid code." }), { status: 401 }));
    const onCancel = vi.fn();
    render(<StepUpModal open onCancel={onCancel} onVerified={vi.fn()} />);

    fireEvent.change(screen.getByLabelText(/Authenticator code/i), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("Invalid code.")).toBeVisible();

    fireEvent.click(screen.getAllByRole("button", { name: "Cancel" })[1]);
    expect(onCancel).toHaveBeenCalled();
  });
});
