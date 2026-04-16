import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Pagination, buildPageList } from "../Pagination";

describe("buildPageList", () => {
  it("shows all pages when total <= 5", () => {
    expect(buildPageList(3, 5)).toEqual([1, 2, 3, 4, 5]);
    expect(buildPageList(1, 1)).toEqual([1]);
    expect(buildPageList(2, 3)).toEqual([1, 2, 3]);
  });

  it("first 3 pages: show 1..3 then ellipsis then last", () => {
    expect(buildPageList(1, 12)).toEqual([1, 2, 3, "...", 12]);
    expect(buildPageList(2, 12)).toEqual([1, 2, 3, "...", 12]);
    expect(buildPageList(3, 12)).toEqual([1, 2, 3, "...", 12]);
  });

  it("last 3 pages: show first then ellipsis then N-2..N", () => {
    expect(buildPageList(12, 12)).toEqual([1, "...", 10, 11, 12]);
    expect(buildPageList(11, 12)).toEqual([1, "...", 10, 11, 12]);
    expect(buildPageList(10, 12)).toEqual([1, "...", 10, 11, 12]);
  });

  it("middle pages: show first ellipsis P-1 P P+1 ellipsis last", () => {
    expect(buildPageList(7, 12)).toEqual([1, "...", 6, 7, 8, "...", 12]);
    expect(buildPageList(5, 12)).toEqual([1, "...", 4, 5, 6, "...", 12]);
  });
});

describe("Pagination", () => {
  it("renders the current page with aria-current=page", () => {
    render(
      <Pagination
        currentPage={1}
        totalPages={12}
        totalCount={47}
        pageSize={4}
        onPageChange={() => {}}
      />,
    );
    const current = screen.getByRole("button", { name: "1" });
    expect(current).toHaveAttribute("aria-current", "page");
  });

  it("renders 'Showing 1 to 4 of 47' summary", () => {
    render(
      <Pagination
        currentPage={1}
        totalPages={12}
        totalCount={47}
        pageSize={4}
        onPageChange={() => {}}
      />,
    );
    expect(screen.getByText(/showing/i)).toHaveTextContent("Showing 1 to 4 of 47");
  });

  it("disables Prev on page 1 and Next on the last page", () => {
    const onPage = vi.fn();
    const { rerender } = render(
      <Pagination
        currentPage={1}
        totalPages={12}
        totalCount={47}
        pageSize={4}
        onPageChange={onPage}
      />,
    );
    expect(screen.getByRole("button", { name: /prev/i })).toBeDisabled();

    rerender(
      <Pagination
        currentPage={12}
        totalPages={12}
        totalCount={47}
        pageSize={4}
        onPageChange={onPage}
      />,
    );
    expect(screen.getByRole("button", { name: /next/i })).toBeDisabled();
  });

  it("calls onPageChange with the clicked number", async () => {
    const onPage = vi.fn();
    render(
      <Pagination
        currentPage={1}
        totalPages={12}
        totalCount={47}
        pageSize={4}
        onPageChange={onPage}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "3" }));
    expect(onPage).toHaveBeenCalledWith(3);
  });
});
