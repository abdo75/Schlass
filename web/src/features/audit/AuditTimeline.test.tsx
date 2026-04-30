import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AuditTimeline } from "./AuditTimeline";
import { fakeEvent } from "./test-helpers";
import type { ListResponse } from "./types";

function response(items: ListResponse["items"]): ListResponse {
  return { items, total: items.length, page: 1, page_size: 25 };
}

describe("AuditTimeline", () => {
  it("renders outcome chip, sentence, actor, and critical badge", () => {
    render(
      <AuditTimeline
        data={response([fakeEvent({ event_type: "oidc.refresh.reuse_detected", outcome: "failure", actor_display: "System", actor_id: null })])}
        onSelect={vi.fn()}
      />,
    );

    expect(screen.getByText("failure")).toBeVisible();
    expect(screen.getByText(/refresh token was reused/i)).toBeVisible();
    expect(screen.getByText(/critical/i)).toBeVisible();
    expect(screen.getByText("System")).toBeVisible();
  });

  it("renders one row per item — no correlation grouping", () => {
    const items = [
      fakeEvent({ id: "evt-1", event_type: "login.succeeded", metadata: { correlation_id: "c-1" } }),
      fakeEvent({ id: "evt-2", event_type: "mfa.challenge_succeeded", metadata: { correlation_id: "c-1" } }),
    ];
    render(<AuditTimeline data={response(items)} onSelect={vi.fn()} />);

    expect(screen.getAllByTestId("audit-event-row")).toHaveLength(2);
    expect(screen.queryByText(/correlated/i)).not.toBeInTheDocument();
    expect(screen.getByText(/passed the multi-factor challenge/i)).toBeVisible();
  });

  it("calls onSelect when a row is clicked", () => {
    const onSelect = vi.fn();
    render(
      <AuditTimeline
        data={response([fakeEvent({ id: "evt-1" })])}
        onSelect={onSelect}
      />,
    );

    fireEvent.click(screen.getByTestId("audit-event-row"));
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: "evt-1" }));
  });
});
