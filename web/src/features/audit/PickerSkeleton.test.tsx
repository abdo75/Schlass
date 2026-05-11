import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PickerSkeleton } from "./PickerSkeleton";

describe("PickerSkeleton", () => {
  it("renders four placeholder rows", () => {
    render(<PickerSkeleton />);
    const root = screen.getByTestId("audit-picker-skeleton");
    expect(root).toHaveAttribute("aria-hidden", "true");
    expect(root.children).toHaveLength(4);
  });
});
