import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, setCsrf } from "../api/client";

afterEach(() => vi.restoreAllMocks());

describe("api client", () => {
  it("sends the CSRF header on state-changing requests only", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response("{}", { status: 200 }));
    setCsrf("tok");
    await api("/x");
    await api("/x", { method: "POST", body: { a: 1 } });
    expect((fetchMock.mock.calls[0][1]!.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
    expect((fetchMock.mock.calls[1][1]!.headers as Record<string, string>)["X-CSRF-Token"]).toBe("tok");
  });
  it("turns validation errors into readable messages", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ detail: [{ loc: ["body", "value"], msg: "invalid target" }] }), { status: 422 }));
    await expect(api("/x", { method: "POST", body: {} })).rejects.toThrow("value: invalid target");
  });
  it("signals an expired session", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ detail: "Not authenticated" }), { status: 401 }));
    const seen = vi.fn();
    window.addEventListener("tls-scan:unauthorized", seen);
    await expect(api("/x")).rejects.toBeInstanceOf(ApiError);
    expect(seen).toHaveBeenCalled();
  });
});
