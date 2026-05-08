import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useAuditList } from "./useAuditQuery";
import type { AuditState } from "./types";

const baseState: AuditState = { view: "all", since: "24h", page: 1, pageSize: 25 };
const okBody = { items: [], total: 0, page: 1, page_size: 25 };

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useAuditList", () => {
  it("rejects invalid response shape", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: "nope" }), { status: 200 }),
    );
    const { result } = renderHook(() => useAuditList(baseState));
    await waitFor(() => expect(result.current.error).not.toBeNull());
    expect(result.current.error?.message).toMatch(/invalid/i);
  });

  it("retry() refetches and resolves the error state", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response("server fire", { status: 500 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(okBody), { status: 200 }));
    const { result } = renderHook(() => useAuditList(baseState));
    await waitFor(() => expect(result.current.error).not.toBeNull());
    act(() => result.current.retry());
    await waitFor(() => expect(result.current.data).not.toBeNull());
    expect(result.current.error).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("ignores AbortError on cleanup", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      });
    });
    const { result, unmount } = renderHook(() => useAuditList(baseState));
    unmount();
    // Yield a tick — error must remain null after the abort rejection settles.
    await new Promise((r) => setTimeout(r, 10));
    expect(result.current.error).toBeNull();
  });
});
