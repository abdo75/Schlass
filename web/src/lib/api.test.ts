import { describe, it, expect } from "vitest";
import { ApiRequestError } from "./api";

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
