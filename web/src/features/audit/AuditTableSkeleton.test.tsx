import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AuditTableSkeleton } from "./AuditTableSkeleton";

describe("AuditTableSkeleton", () => {
  it("renders eight shimmer rows matching the timeline columns", () => {
    render(<AuditTableSkeleton />);
    const root = screen.getByTestId("audit-table-skeleton");
    expect(root).toHaveAttribute("aria-hidden", "true");
    const rows = root.querySelectorAll("tbody tr");
    expect(rows).toHaveLength(8);
  });
});
