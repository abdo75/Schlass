import { renderHook, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { ReactNode } from "react";
import { useUrlState, stateToParams } from "./useUrlState";

function wrap(initial: string) {
  return ({ children }: { children: ReactNode }) => (
    <MemoryRouter initialEntries={[initial]}>{children}</MemoryRouter>
  );
}

describe("useUrlState", () => {
  it("parses a full set of valid query params", () => {
    const { result } = renderHook(() => useUrlState(), {
      wrapper: wrap("/?view=admin&since=7d&actor=alice&outcome=denied&page=2&page_size=50"),
    });
    expect(result.current.state.view).toBe("admin");
    expect(result.current.state.since).toBe("7d");
    expect(result.current.state.actor).toBe("alice");
    expect(result.current.state.outcome).toBe("denied");
    expect(result.current.state.page).toBe(2);
    expect(result.current.state.pageSize).toBe(50);
  });

  it("falls back to defaults for unknown view values", () => {
    const { result } = renderHook(() => useUrlState(), {
      wrapper: wrap("/?view=hax&outcome=xyz"),
    });
    expect(result.current.state.view).toBe("all");
    expect(result.current.state.outcome).toBeUndefined();
  });

  it("clamps non-numeric page values to defaults", () => {
    const { result } = renderHook(() => useUrlState(), {
      wrapper: wrap("/?page=abc&page_size=-1"),
    });
    expect(result.current.state.page).toBe(1);
    expect(result.current.state.pageSize).toBe(25);
  });

  it("set() round-trips through stateToParams without loss", () => {
    const { result } = renderHook(() => useUrlState(), { wrapper: wrap("/") });
    act(() => result.current.set({ actor: "bob", outcome: "success", page: 3 }));
    const serialized = stateToParams(result.current.state).toString();
    expect(serialized).toContain("actor=bob");
    expect(serialized).toContain("outcome=success");
    expect(serialized).toContain("page=3");
  });
});
