import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

const languages = [
  { code: "en", label: "EN" },
  { code: "fr", label: "FR" },
  { code: "de", label: "DE" },
] as const;

export function LanguageSwitcher() {
  const { i18n } = useTranslation();

  return (
    <div className="absolute top-4 left-4 flex gap-1">
      {languages.map(({ code, label }) => (
        <Button
          key={code}
          variant={i18n.language.startsWith(code) ? "default" : "ghost"}
          size="sm"
          onClick={() => i18n.changeLanguage(code)}
          className="h-8 w-8 p-0 text-xs"
        >
          {label}
        </Button>
      ))}
    </div>
  );
}
