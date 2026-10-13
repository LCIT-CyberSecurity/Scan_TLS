// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { en } from "../i18n/en";
import { fr } from "../i18n/fr";

afterEach(cleanup);
describe("exclusions strings", () => {
  it("are defined in every language with the same placeholders", () => {
    for (const key of ["excl.label", "excl.hint", "excl.run", "excl.removed", "excl.partial", "excl.settingsTitle"] as const) {
      expect(en[key]).toBeTruthy();
      expect(fr[key]).toBeTruthy();
      expect(fr[key].match(/\{\w+\}/g) ?? []).toEqual(en[key].match(/\{\w+\}/g) ?? []);
    }
    expect(render(<span>{fr["excl.label"]}</span>).container).toHaveTextContent("Exclusions");
    screen.getByText(/Exclusions/);
  });
});
