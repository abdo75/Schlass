import { describe, it, expect } from "vitest";
import { renderHook } from "@testing-library/react";
import React from "react";
import type { ReactNode } from "react";
import { AuthContext } from "./AuthContext";
import { usePermission } from "./usePermission";
import { PERMISSIONS } from "./permissions";
import type { AuthUser } from "./api";

function wrapperWith(user: AuthUser | null): (props: { children: ReactNode }) => React.ReactElement {
  return ({ children }) => (
    <AuthContext.Provider
      value={{
        user,
        loading: false,
        // eslint-disable-next-line @typescript-eslint/require-await
        login: async () => (user ?? ({ id: "", email: "", role: "user", force_password_change: false } as AuthUser)),
        logout: async () => {},
        refreshUser: async () => {},
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

describe("usePermission", () => {
  it("returns true when super_admin checks an admin permission", () => {
    const user: AuthUser = {
      id: "abc",
      email: "a@x.com",
      role: "super_admin",
      force_password_change: false,
    };
    const { result } = renderHook(() => usePermission(PERMISSIONS.USERS_CREATE), {
      wrapper: wrapperWith(user),
    });
    expect(result.current).toBe(true);
  });

  it("returns false when role=user checks an admin permission", () => {
    const user: AuthUser = {
      id: "abc",
      email: "a@x.com",
      role: "user",
      force_password_change: false,
    };
    const { result } = renderHook(() => usePermission(PERMISSIONS.USERS_CREATE), {
      wrapper: wrapperWith(user),
    });
    expect(result.current).toBe(false);
  });

  it("returns false when no user is authenticated", () => {
    const { result } = renderHook(() => usePermission(PERMISSIONS.USERS_CREATE), {
      wrapper: wrapperWith(null),
    });
    expect(result.current).toBe(false);
  });
});
