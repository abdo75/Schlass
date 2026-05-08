import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AuditCalendar, type AuditRange } from "./AuditCalendar";

const range: AuditRange = {
  from: new Date(2026, 3, 22, 9, 0),
  to: new Date(2026, 3, 25, 23, 59),
};

describe("AuditCalendar", () => {
  it("renders day grid with range and lets From then To select dates", () => {
    const onChange = vi.fn();
    render(<AuditCalendar value={range} onChange={onChange} />);

    expect(screen.getByRole("button", { name: "22" })).toHaveClass("is-range-start");
    expect(screen.getByRole("button", { name: "25" })).toHaveClass("is-range-end");

    fireEvent.click(screen.getByRole("button", { name: "from" }));
    fireEvent.click(screen.getByRole("button", { name: "20" }));
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ from: expect.any(Date) }));

    fireEvent.click(screen.getByRole("button", { name: "to" }));
    fireEvent.click(screen.getByRole("button", { name: "26" }));
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ to: expect.any(Date) }));
  });

  it("switches month and year views and disables future years", () => {
    render(<AuditCalendar value={range} onChange={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: /april/i }));
    expect(screen.getByRole("button", { name: "Jan" })).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Apr" }));
    fireEvent.click(screen.getByRole("button", { name: "2026" }));
    const nextYear = String(new Date().getFullYear() + 1);
    expect(screen.getByRole("button", { name: nextYear })).toBeDisabled();
  });

  it("ArrowRight moves focus to the next day", () => {
    render(<AuditCalendar value={range} onChange={vi.fn()} />);
    const day22 = screen.getByRole("button", { name: "22" });
    day22.focus();
    fireEvent.keyDown(day22, { key: "ArrowRight" });
    expect(screen.getByRole("button", { name: "23" })).toHaveFocus();
  });

  it("ArrowDown moves focus by 7 days", () => {
    render(<AuditCalendar value={range} onChange={vi.fn()} />);
    const day22 = screen.getByRole("button", { name: "22" });
    day22.focus();
    fireEvent.keyDown(day22, { key: "ArrowDown" });
    expect(screen.getByRole("button", { name: "29" })).toHaveFocus();
  });

  it("edits and picks time values", () => {
    const onChange = vi.fn();
    render(<AuditCalendar value={range} onChange={onChange} />);

    const fromRow = screen.getByTestId("time-row-from");
    const hourInput = within(fromRow).getByLabelText("from hour");
    fireEvent.change(hourInput, { target: { value: "99" } });
    fireEvent.blur(hourInput);
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ from: expect.any(Date) }));

    fireEvent.click(within(fromRow).getByRole("button", { name: /pick from minute/i }));
    fireEvent.click(screen.getByRole("button", { name: "55" }));
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ from: expect.any(Date) }));
  });
});
