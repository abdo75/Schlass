import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";
import { ExportMenu } from "./ExportMenu";
import type { AuditState } from "./types";

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

const state: AuditState = { view: "all", since: "24h", page: 1, pageSize: 25 };

afterEach(() => {
  vi.restoreAllMocks();
  vi.mocked(toast.success).mockReset();
  vi.mocked(toast.error).mockReset();
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
      .mockResolvedValueOnce(new Response("id,event_type\n", { status: 200, headers: { "Content-Type": "application/gzip" } }));

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

  it("renders CSV, JSON, and CAEP SET menu items", () => {
    render(<ExportMenu state={state} />);
    fireEvent.click(screen.getByRole("button", { name: /Export/i }));

    expect(screen.getByRole("menuitem", { name: "CSV" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "JSON" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "CAEP SET" })).toBeInTheDocument();
  });

  it("downloads a .tar.gz bundle and toasts success", async () => {
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:bundle");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    vi.spyOn(document.body, "append");
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(new Uint8Array([0x1f, 0x8b]), { status: 200, headers: { "Content-Type": "application/gzip" } })
    );

    render(<ExportMenu state={state} />);
    fireEvent.click(screen.getByRole("button", { name: /Export/i }));
    fireEvent.click(screen.getByRole("menuitem", { name: "CSV" }));

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith("Export ready."));
  });

  it("toasts an error and re-enables the trigger when the export call fails", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "INTERNAL", message: "Disk full" }), { status: 500 }),
    );

    render(<ExportMenu state={state} />);
    fireEvent.click(screen.getByRole("button", { name: /Export/i }));
    fireEvent.click(screen.getByRole("menuitem", { name: "CSV" }));

    await waitFor(() => expect(toast.error).toHaveBeenCalled());
    expect(vi.mocked(toast.error).mock.calls[0][0]).toMatch(/Export failed/);
    // Trigger should re-enable after the failure resolves.
    await waitFor(() => expect(screen.getByRole("button", { name: /Export/i })).not.toBeDisabled());
  });

  it("sends format=caep when CAEP SET is clicked", async () => {
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:bundle");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    vi.spyOn(document.body, "append");
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(new Uint8Array([0x1f, 0x8b]), { status: 200, headers: { "Content-Type": "application/gzip" } })
    );

    render(<ExportMenu state={state} />);
    fireEvent.click(screen.getByRole("button", { name: /Export/i }));
    fireEvent.click(screen.getByRole("menuitem", { name: "CAEP SET" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const body = JSON.parse(fetchMock.mock.calls[0][1]?.body as string) as Record<string, unknown>;
    expect(body.format).toBe("caep");
  });

  it("encodes the chosen format into the filename before the .tar.gz suffix", async () => {
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:bundle");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const append = vi.spyOn(document.body, "append");
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(new Uint8Array(), { status: 200, headers: { "Content-Type": "application/gzip" } })
    );

    render(<ExportMenu state={state} />);
    fireEvent.click(screen.getByRole("button", { name: /Export/i }));
    fireEvent.click(screen.getByRole("menuitem", { name: "JSON" }));

    await waitFor(() => expect(append).toHaveBeenCalled());
    const anchor = (append.mock.calls[0][0] as HTMLAnchorElement);
    expect(anchor.download).toMatch(/^audit-log-\d{8}-\d{4}-jsonl\.tar\.gz$/);
  });
});
