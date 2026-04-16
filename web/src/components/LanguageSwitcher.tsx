import { useTranslation } from "react-i18next";

const LANGUAGES: ReadonlyArray<{ code: "en" | "fr" | "de"; label: string }> = [
  { code: "en", label: "EN" },
  { code: "fr", label: "FR" },
  { code: "de", label: "DE" },
];

export function LanguageSwitcher() {
  const { i18n } = useTranslation();
  const current = i18n.language.slice(0, 2) as "en" | "fr" | "de";

  const handleChange = async (code: "en" | "fr" | "de") => {
    await i18n.changeLanguage(code);
    localStorage.setItem("schlass-language", code);
  };

  return (
    <div className="inline-flex h-8 items-center gap-0.5 rounded-lg border border-border bg-background p-0.5">
      {LANGUAGES.map(({ code, label }) => {
        const isCurrent = current === code;
        return (
          <button
            key={code}
            type="button"
            aria-pressed={isCurrent}
            onClick={() => void handleChange(code)}
            className={`inline-flex h-7 items-center rounded-md px-2.5 text-xs font-semibold transition-colors ${
              isCurrent
                ? "bg-accent text-accent-foreground"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {label}
          </button>
        );
      })}
    </div>
  );
}
