export function relativeTime(date: Date, locale: string): string {
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const divisions: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["year", 60 * 60 * 24 * 365],
    ["month", 60 * 60 * 24 * 30],
    ["day", 60 * 60 * 24],
    ["hour", 60 * 60],
    ["minute", 60],
    ["second", 1],
  ];
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  for (const [unit, amount] of divisions) {
    if (Math.abs(seconds) >= amount || unit === "second") {
      return formatter.format(Math.round(seconds / amount), unit);
    }
  }
  return formatter.format(0, "second");
}
