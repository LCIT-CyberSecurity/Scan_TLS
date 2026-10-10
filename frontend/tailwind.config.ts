import type { Config } from "tailwindcss";

// Tailwind reads LCIT-Sign's design tokens (CSS variables), so light/dark and the five palettes keep working.
const v = (name: string) => `var(--${name})`;
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: v("background"), surface: v("surface"), "surface-2": v("surface-secondary"), sunken: v("surface-sunken"),
        border: v("border"), "border-strong": v("border-strong"), hairline: v("hairline"),
        fg: v("text-primary"), "fg-2": v("text-secondary"), muted: v("text-muted"), faint: v("text-faint"),
        primary: { DEFAULT: v("primary"), hover: v("primary-hover"), soft: v("primary-soft"), line: v("primary-line"), fg: v("text-on-accent") },
        success: { DEFAULT: v("success"), soft: v("success-soft"), line: v("success-line") },
        warning: { DEFAULT: v("warning"), soft: v("warning-soft"), line: v("warning-line") },
        danger: { DEFAULT: v("danger"), soft: v("danger-soft"), line: v("danger-line") },
        info: { DEFAULT: v("info"), soft: v("info-soft"), line: v("info-line") },
      },
      borderRadius: { sm: v("radius-sm"), DEFAULT: v("radius"), lg: v("radius-lg"), xl: v("radius-xl") },
      boxShadow: { sm: v("shadow-sm"), md: v("shadow-md"), lg: v("shadow-lg") },
      fontFamily: { sans: ['"Inter Variable"', "system-ui", "sans-serif"] },
    },
  },
  plugins: [],
} satisfies Config;
