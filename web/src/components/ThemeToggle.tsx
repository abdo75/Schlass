import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";

type Theme = "light" | "dark" | "system";

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => {
    if (typeof window === "undefined") return "system";
    return (localStorage.getItem("schlass-theme") as Theme) || "system";
  });

  useEffect(() => {
    const root = document.documentElement;
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

    const apply = () => {
      const isDark = theme === "dark" || (theme === "system" && mediaQuery.matches);
      root.classList.toggle("dark", isDark);
    };

    apply();
    localStorage.setItem("schlass-theme", theme);

    // Only subscribe to OS-level changes when the user picked "system".
    // Explicit light/dark should not flip when the OS preference changes.
    if (theme !== "system") return;
    mediaQuery.addEventListener("change", apply);
    return () => mediaQuery.removeEventListener("change", apply);
  }, [theme]);

  const cycle = () => {
    setTheme((prev) => {
      if (prev === "light") return "dark";
      if (prev === "dark") return "system";
      return "light";
    });
  };

  const label = theme === "light" ? "☀️" : theme === "dark" ? "🌙" : "💻";

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={cycle}
      className="absolute top-4 right-4"
      aria-label="Toggle theme"
    >
      {label}
    </Button>
  );
}
