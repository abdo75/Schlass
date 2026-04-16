import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import "@/i18n";
import { StatusBadge } from "../status-badge";

describe("StatusBadge", () => {
  it("renders Active with a primary-colored dot and foreground label", () => {
    render(<StatusBadge status="active" />);
    expect(screen.getByText(/active/i)).toBeInTheDocument();
    const dot = screen.getByTestId("status-dot");
    expect(dot).toHaveClass("bg-primary");
  });

  it("renders Disabled with a destructive-colored dot and muted text", () => {
    render(<StatusBadge status="disabled" />);
    expect(screen.getByText(/disabled/i)).toBeInTheDocument();
    const dot = screen.getByTestId("status-dot");
    expect(dot).toHaveClass("bg-destructive");
  });

  it("applies muted-foreground text color in the disabled variant", () => {
    const { container } = render(<StatusBadge status="disabled" />);
    const root = container.firstChild as HTMLElement;
    expect(root).toHaveClass("text-muted-foreground");
  });

  it("does NOT apply muted-foreground text color in the active variant", () => {
    const { container } = render(<StatusBadge status="active" />);
    const root = container.firstChild as HTMLElement;
    expect(root).not.toHaveClass("text-muted-foreground");
  });
});
