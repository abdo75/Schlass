import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ActorPicker } from "./ActorPicker";
import { EventTypePicker } from "./EventTypePicker";
import { TargetPicker } from "./TargetPicker";
import type { AuditState } from "./types";

const state: AuditState = { view: "all", since: "24h", page: 1, pageSize: 25 };

afterEach(() => {
  vi.restoreAllMocks();
});

describe("audit pickers", () => {
  it("filters actors and selects by email", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      users: [{ actor_id: "1", actor_email: "admin@example.com", count: 3 }],
      system_count: 1,
    })));
    const onSelect = vi.fn();
    render(<ActorPicker state={state} onSelect={onSelect} />);

    fireEvent.change(screen.getByPlaceholderText(/search actors/i), { target: { value: "admin" } });
    await screen.findByRole("option", { name: /admin@example.com/i });
    fireEvent.click(screen.getByRole("option", { name: /admin@example.com/i }));
    expect(onSelect).toHaveBeenCalledWith("admin@example.com");
  });

  it("selects target type, searches targets, and applies an id", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      items: [{ target_id: "client-1", display: "Grafana", extra: "public" }],
    })));
    const onSelect = vi.fn();
    render(<TargetPicker state={state} onSelect={onSelect} />);

    fireEvent.click(screen.getByRole("option", { name: "Client" }));
    await screen.findByPlaceholderText(/search targets/i);
    fireEvent.change(screen.getByPlaceholderText(/search targets/i), { target: { value: "graf" } });
    fireEvent.click(await screen.findByRole("option", { name: /grafana/i }));
    expect(onSelect).toHaveBeenCalledWith({ target_type: "client", target_id: "client-1", display: "Grafana" });
  });

  it("applies grouped event type selections", async () => {
    const onApply = vi.fn();
    render(<EventTypePicker selected={[]} onApply={onApply} />);

    // Groups start collapsed for a cleaner overview — expand Login first.
    await waitFor(() => expect(screen.getByRole("button", { name: /login/i })).toBeVisible());
    fireEvent.click(screen.getByRole("button", { name: /login/i }));
    fireEvent.click(screen.getByLabelText("Success"));
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(onApply).toHaveBeenCalledWith(["login.succeeded"]);
  });
});
