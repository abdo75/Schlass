import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AuditFilterBar } from "./AuditFilterBar";
import type { AuditState } from "./types";

const baseState: AuditState = { view: "all", since: "24h", page: 1, pageSize: 25 };

describe("AuditFilterBar", () => {
  it("clicking an active chip clears its filter", () => {
    const onChange = vi.fn();
    render(
      <AuditFilterBar
        state={{ ...baseState, actor: "admin@example.com", event_types: ["login.succeeded"] }}
        onChange={onChange}
      />,
    );

    expect(screen.getByText(/Actor: admin@example\.com/)).toBeVisible();
    expect(screen.getByText(/Event type: 1/)).toBeVisible();

    // Whole chip is the click target — no separate × button.
    fireEvent.click(screen.getByRole("button", { name: /clear filter: actor: admin@example\.com/i }));
    expect(onChange).toHaveBeenCalledWith({ actor: undefined, page: 1 });

    fireEvent.click(screen.getByRole("button", { name: /clear filters/i }));
    expect(onChange).toHaveBeenCalledWith({
      actor: undefined,
      target_type: undefined,
      target_id: undefined,
      event_types: undefined,
      outcome: undefined,
      q: undefined,
      page: 1,
    });
  });

  it("opens the actor picker from the dashed chip", () => {
    render(<AuditFilterBar state={baseState} onChange={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: "+ Actor" }));
    expect(screen.getByPlaceholderText(/search actors/i)).toBeVisible();
  });
});
