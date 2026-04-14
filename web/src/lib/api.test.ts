import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiFetch, ApiRequestError } from "./api";

describe("ApiRequestError", () => {
  it("stores status and error code", () => {
    const err = new ApiRequestError(400, {
      error: "VALIDATION_ERROR",
      message: "Invalid input",
    });

    expect(err.status).toBe(400);
    expect(err.code).toBe("VALIDATION_ERROR");
    expect(err.message).toBe("Invalid input");
  });

  it("extends Error", () => {
    const err = new ApiRequestError(500, {
      error: "INTERNAL_ERROR",
      message: "Something broke",
    });

    expect(err).toBeInstanceOf(Error);
  });
});

describe("apiFetch", () => {
  let dispatchSpy: ReturnType<typeof setupDispatchSpy>;

  function setupDispatchSpy() {
    return vi.spyOn(window, "dispatchEvent");
  }

  beforeEach(() => {
    dispatchSpy = setupDispatchSpy();
  });

  afterEach(() => {
    dispatchSpy.mockRestore();
    vi.restoreAllMocks();
  });

  it("dispatches schlass:unauthorized on 401", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ error: "INVALID_SESSION", message: "nope" }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );

    await expect(apiFetch("/api/me")).rejects.toBeInstanceOf(ApiRequestError);

    const dispatched = dispatchSpy.mock.calls.map((call) => call[0].type);
    expect(dispatched).toContain("schlass:unauthorized");
  });

  it("does NOT dispatch schlass:unauthorized on 200", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await apiFetch("/api/me");

    const dispatched = dispatchSpy.mock.calls.map((call) => call[0].type);
    expect(dispatched).not.toContain("schlass:unauthorized");
  });

  it("does NOT dispatch schlass:unauthorized on non-401 errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ error: "VALIDATION_ERROR", message: "bad" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );

    await expect(apiFetch("/api/me")).rejects.toBeInstanceOf(ApiRequestError);

    const dispatched = dispatchSpy.mock.calls.map((call) => call[0].type);
    expect(dispatched).not.toContain("schlass:unauthorized");
  });
});
