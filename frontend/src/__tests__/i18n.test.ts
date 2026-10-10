import { describe, expect, it } from "vitest";
import { de } from "../i18n/de";
import { en } from "../i18n/en";
import { detectLocale } from "../i18n";
import { fr } from "../i18n/fr";

describe("translations", () => {
  it("fr and de define exactly the keys of en, none empty (except the empty phase)", () => {
    const keys = Object.keys(en).sort();
    expect(Object.keys(fr).sort()).toEqual(keys);
    expect(Object.keys(de).sort()).toEqual(keys);
    for (const dict of [en, fr, de]) for (const k of keys) if (k !== "phase.") expect((dict as Record<string, string>)[k], k).not.toBe("");
  });
  it("keeps the same placeholders in every language", () => {
    const placeholders = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join();
    for (const k of Object.keys(en) as (keyof typeof en)[]) {
      expect(placeholders(fr[k]), k).toBe(placeholders(en[k]));
      expect(placeholders(de[k]), k).toBe(placeholders(en[k]));
    }
  });
});

describe("locale detection", () => {
  const withBrowser = (lang: string, fn: () => void) => {
    Object.defineProperty(navigator, "languages", { value: [lang], configurable: true });
    window.localStorage.clear();
    fn();
  };
  it("uses the browser language when supported", () => withBrowser("de-DE", () => expect(detectLocale()).toBe("de")));
  it("falls back to English when unsupported", () => withBrowser("ja-JP", () => expect(detectLocale()).toBe("en")));
  it("an explicit choice wins over the browser", () => withBrowser("de-DE", () => expect(detectLocale("fr")).toBe("fr")));
});
