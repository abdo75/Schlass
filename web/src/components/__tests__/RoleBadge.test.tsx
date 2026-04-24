import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import "@/i18n";
import { RoleBadge } from "../RoleBadge";

describe("RoleBadge", () => {
  it("renders Admin with accent colors", () => {
    render(<RoleBadge role="super_admin" />);
    const el = screen.getByText(/admin/i);
    expect(el).toBeInTheDocument();
    expect(el).toHaveClass("bg-accent");
  });

  it("renders User with muted colors", () => {
    render(<RoleBadge role="user" />);
    const el = screen.getByText(/^user$/i);
    expect(el).toBeInTheDocument();
    expect(el).toHaveClass("bg-muted");
  });
});
