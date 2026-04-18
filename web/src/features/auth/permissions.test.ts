import { describe, it, expect } from "vitest";
import { PERMISSIONS, permissionsForRole } from "./permissions";

describe("permissions catalog", () => {
  it("defines 12 permission strings", () => {
    const values = Object.values(PERMISSIONS);
    expect(values.length).toBe(12);
    expect(new Set(values).size).toBe(12); // all unique
  });

  it("includes signing_keys.rotate", () => {
    expect(Object.values(PERMISSIONS)).toContain("signing_keys.rotate");
  });

  it("uses dot-delimited names", () => {
    for (const value of Object.values(PERMISSIONS)) {
      expect(value).toMatch(/^[a-z_]+(\.[a-z_]+)+$/);
    }
  });
});

describe("permissionsForRole", () => {
  it("super_admin holds all 12 permissions", () => {
    expect(permissionsForRole("super_admin").length).toBe(12);
    expect(permissionsForRole("super_admin")).toContain("signing_keys.rotate");
  });

  it("user holds no permissions", () => {
    expect(permissionsForRole("user").length).toBe(0);
  });

  it("unknown role holds no permissions", () => {
    expect(permissionsForRole("typo_role").length).toBe(0);
  });
});
