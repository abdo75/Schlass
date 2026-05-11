export const PRESETS = [
  { labelKey: "audit.timepicker.preset.lastHour", value: "1h" },
  { labelKey: "audit.timepicker.preset.last24h", value: "24h" },
  { labelKey: "audit.timepicker.preset.last7d", value: "7d" },
  { labelKey: "audit.timepicker.preset.last30d", value: "30d" },
] as const;

export type PresetValue = (typeof PRESETS)[number]["value"];
