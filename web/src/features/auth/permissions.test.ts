import { describe, it, expect } from "vitest";
import { PERMISSIONS, permissionsForRole } from "./permissions";

describe("permissions catalog", () => {
  it("defines 13 permission strings", () => {
    const values = Object.values(PERMISSIONS);
    expect(values.length).toBe(13);
    expect(new Set(values).size).toBe(13); // all unique
  });

  it("includes signing_keys.rotate", () => {
    expect(Object.values(PERMISSIONS)).toContain("signing_keys.rotate");
  });

  it("includes signing_keys.retire", () => {
    expect(Object.values(PERMISSIONS)).toContain("signing_keys.retire");
  });

  it("uses dot-delimited names", () => {
    for (const value of Object.values(PERMISSIONS)) {
      expect(value).toMatch(/^[a-z_]+(\.[a-z_]+)+$/);
    }
  });
});

describe("permissionsForRole", () => {
  it("super_admin holds all 13 permissions", () => {
    expect(permissionsForRole("super_admin").length).toBe(13);
    expect(permissionsForRole("super_admin")).toContain("signing_keys.rotate");
    expect(permissionsForRole("super_admin")).toContain("signing_keys.retire");
  });

  it("user holds no permissions", () => {
    expect(permissionsForRole("user").length).toBe(0);
  });

  it("unknown role holds no permissions", () => {
    expect(permissionsForRole("typo_role").length).toBe(0);
  });
});
