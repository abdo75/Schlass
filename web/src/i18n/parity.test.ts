import { describe, expect, it } from "vitest";
import en from "./locales/en.json";
import fr from "./locales/fr.json";
import de from "./locales/de.json";

type Bundle = Record<string, unknown>;

function flattenKeys(obj: Bundle, prefix = ""): string[] {
  return Object.entries(obj).flatMap(([k, v]) => {
    const path = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      return flattenKeys(v as Bundle, path);
    }
    return [path];
  });
}

// i18next plural suffixes that can vary by locale (English has _one/_other,
// French/German also align). Comparing the bare key plus suffix variants is
// noisy; collapse all `<key>_<suffix>` to `<key>` so locales with different
// CLDR plural categories (e.g. zh has only `_other`) don't false-positive.
const PLURAL_SUFFIX = /_(zero|one|two|few|many|other)$/;

function canonicalise(keys: string[]): Set<string> {
  return new Set(keys.map((k) => k.replace(PLURAL_SUFFIX, "")));
}

describe("i18n parity", () => {
  const enKeys = canonicalise(flattenKeys(en as Bundle));
  const frKeys = canonicalise(flattenKeys(fr as Bundle));
  const deKeys = canonicalise(flattenKeys(de as Bundle));

  it("fr.json covers every en.json key", () => {
    const missing = [...enKeys].filter((k) => !frKeys.has(k)).sort();
    expect(missing, `fr is missing keys: ${missing.join(", ")}`).toEqual([]);
  });

  it("de.json covers every en.json key", () => {
    const missing = [...enKeys].filter((k) => !deKeys.has(k)).sort();
    expect(missing, `de is missing keys: ${missing.join(", ")}`).toEqual([]);
  });
});
