import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AuditTimePicker } from "./AuditTimePicker";
import type { AuditState } from "./types";

const state: AuditState = { view: "all", since: "24h", page: 1, pageSize: 25 };

describe("AuditTimePicker", () => {
  it("applies presets", () => {
    const onChange = vi.fn();
    render(<AuditTimePicker state={state} onChange={onChange} />);

    // Picker renders directly (anchor + open/close lives in AuditFilterBar).
    fireEvent.click(screen.getByRole("button", { name: /last 7 days/i }));
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(onChange).toHaveBeenCalledWith({ since: "7d", until: undefined });
  });

  it("applies a custom range with since and until", () => {
    const onChange = vi.fn();
    render(<AuditTimePicker state={state} onChange={onChange} />);

    fireEvent.click(screen.getByRole("button", { name: /custom range/i }));
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(onChange).toHaveBeenCalledWith({
      since: expect.stringMatching(/T/),
      until: expect.stringMatching(/T/),
    });
  });
});
