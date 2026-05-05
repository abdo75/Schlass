import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ExportMenu } from "./ExportMenu";
import type { AuditState } from "./types";

const state: AuditState = { view: "all", since: "24h", page: 1, pageSize: 25 };

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ExportMenu", () => {
  it("opens step-up on 401, verifies, and retries export", async () => {
    const createObjectURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:csv");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const append = vi.spyOn(document.body, "append");
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: "STEPUP_REQUIRED", message: "Recent MFA verification is required." }), { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }))
      .mockResolvedValueOnce(new Response("id,event_type\n", { status: 200, headers: { "Content-Type": "text/csv" } }));

    render(<ExportMenu state={state} />);
    fireEvent.click(screen.getByRole("button", { name: /Export/i }));
    fireEvent.click(screen.getByRole("menuitem", { name: "CSV" }));

    expect(await screen.findByRole("dialog")).toBeVisible();
    fireEvent.change(screen.getByLabelText(/Authenticator code/i), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    expect(fetchMock.mock.calls[0][0]).toBe("/api/audit/export");
    expect(fetchMock.mock.calls[1][0]).toBe("/api/auth/stepup/challenge");
    expect(fetchMock.mock.calls[2][0]).toBe("/api/audit/export");
    expect(createObjectURL).toHaveBeenCalled();
    expect(append).toHaveBeenCalled();
    expect(click).toHaveBeenCalled();
  });
});
