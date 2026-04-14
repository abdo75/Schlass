import "@testing-library/jest-dom/vitest";
import "@/i18n";

// jsdom does not implement window.matchMedia — polyfill for components that
// read system color-scheme preference (e.g. ThemeToggle).
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}
