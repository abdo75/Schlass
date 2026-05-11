import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AuditTabs } from "./AuditTabs";
import type { AuditState } from "./types";

const baseState: AuditState = { view: "all", since: "24h", page: 1, pageSize: 25 };

describe("AuditTabs a11y", () => {
  it("uses roving tabindex and reports aria-selected", () => {
    render(<AuditTabs state={baseState} onChange={vi.fn()} />);
    const allTab = screen.getByRole("tab", { name: /all events/i });
    const signInTab = screen.getByRole("tab", { name: /sign-in activity/i });
    expect(allTab).toHaveAttribute("aria-selected", "true");
    expect(allTab).toHaveAttribute("tabindex", "0");
    expect(signInTab).toHaveAttribute("aria-selected", "false");
    expect(signInTab).toHaveAttribute("tabindex", "-1");
  });

  it("ArrowRight on the active tab triggers onChange to the next view", () => {
    const onChange = vi.fn();
    render(<AuditTabs state={baseState} onChange={onChange} />);
    fireEvent.keyDown(screen.getByRole("tablist"), { key: "ArrowRight" });
    expect(onChange).toHaveBeenCalledWith({ view: "sign-in", page: 1 });
  });

  it("ArrowLeft on the first tab wraps to the last view", () => {
    const onChange = vi.fn();
    render(<AuditTabs state={baseState} onChange={onChange} />);
    fireEvent.keyDown(screen.getByRole("tablist"), { key: "ArrowLeft" });
    expect(onChange).toHaveBeenCalledWith({ view: "client", page: 1 });
  });

  it("clicking a tab calls onChange with the matching view", () => {
    const onChange = vi.fn();
    render(<AuditTabs state={baseState} onChange={onChange} />);
    fireEvent.click(screen.getByRole("tab", { name: /admin actions/i }));
    expect(onChange).toHaveBeenCalledWith({ view: "admin", page: 1 });
  });

  it("End key jumps to the last tab", () => {
    const onChange = vi.fn();
    render(<AuditTabs state={baseState} onChange={onChange} />);
    fireEvent.keyDown(screen.getByRole("tablist"), { key: "End" });
    expect(onChange).toHaveBeenCalledWith({ view: "client", page: 1 });
  });
});
