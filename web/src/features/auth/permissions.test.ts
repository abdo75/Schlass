import { describe, it, expect } from "vitest";
import { PERMISSIONS, permissionsForRole } from "./permissions";

describe("permissions catalog", () => {
  it("defines 18 permission strings", () => {
    const values = Object.values(PERMISSIONS);
    expect(values.length).toBe(18);
    expect(new Set(values).size).toBe(18); // all unique
  });

  it("includes split audit permissions", () => {
    expect(Object.values(PERMISSIONS)).toEqual(expect.arrayContaining(["audit.view", "audit.export", "audit.admin"]));
  });

  it("includes signing_keys.rotate", () => {
    expect(Object.values(PERMISSIONS)).toContain("signing_keys.rotate");
  });

  it("includes signing_keys.retire", () => {
    expect(Object.values(PERMISSIONS)).toContain("signing_keys.retire");
  });

  it("includes settings.read", () => {
    expect(Object.values(PERMISSIONS)).toContain("settings.read");
  });

  it("includes settings.write", () => {
    expect(Object.values(PERMISSIONS)).toContain("settings.write");
  });

  it("uses dot-delimited names", () => {
    for (const value of Object.values(PERMISSIONS)) {
      expect(value).toMatch(/^[a-z_]+(\.[a-z_]+)+$/);
    }
  });
});

describe("permissionsForRole", () => {
  it("super_admin holds all 18 permissions", () => {
    expect(permissionsForRole("super_admin").length).toBe(18);
    expect(permissionsForRole("super_admin")).toContain("audit.view");
    expect(permissionsForRole("super_admin")).toContain("audit.export");
    expect(permissionsForRole("super_admin")).toContain("audit.admin");
    expect(permissionsForRole("super_admin")).toContain("signing_keys.rotate");
    expect(permissionsForRole("super_admin")).toContain("signing_keys.retire");
    expect(permissionsForRole("super_admin")).toContain("settings.read");
    expect(permissionsForRole("super_admin")).toContain("settings.write");
  });

  it("user holds no permissions", () => {
    expect(permissionsForRole("user").length).toBe(0);
  });

  it("unknown role holds no permissions", () => {
    expect(permissionsForRole("typo_role").length).toBe(0);
  });
});
