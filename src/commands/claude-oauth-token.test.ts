import { describe, expect, it, vi } from "vitest";
import {
  buildClaudeOAuthUrl,
  createTokenReference,
  exchangeClaudeOAuthCode,
  generatePkceParams,
  loginClaudeOAuth,
  refreshClaudeOAuthToken,
} from "./claude-oauth-token.js";

describe("generatePkceParams", () => {
  it("returns codeVerifier, codeChallenge, and state", () => {
    const params = generatePkceParams();
    expect(params.codeVerifier).toBeTruthy();
    expect(params.codeChallenge).toBeTruthy();
    expect(params.state).toBeTruthy();
    expect(params.codeVerifier).not.toBe(params.state);
  });

  it("generates unique values on each call", () => {
    const a = generatePkceParams();
    const b = generatePkceParams();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
    expect(a.state).not.toBe(b.state);
  });
});

describe("buildClaudeOAuthUrl", () => {
  it("builds a valid authorization URL", () => {
    const url = buildClaudeOAuthUrl({
      codeChallenge: "test-challenge",
      state: "test-state",
    });
    expect(url).toContain("https://claude.ai/oauth/authorize?");
    expect(url).toContain("code_challenge=test-challenge");
    expect(url).toContain("state=test-state");
    expect(url).toContain("response_type=code");
    expect(url).toContain("code_challenge_method=S256");
    expect(url).toContain("client_id=");
    expect(url).toContain("redirect_uri=");
    expect(url).toContain("scope=");
  });
});

describe("exchangeClaudeOAuthCode", () => {
  it("exchanges code for access token (JSON response)", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: "sk-ant-oat01-test-token",
          refresh_token: "rt-test",
          expires_in: 3600,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", mockFetch);

    const result = await exchangeClaudeOAuthCode({
      code: "auth-code",
      codeVerifier: "verifier",
    });

    expect(result.accessToken).toBe("sk-ant-oat01-test-token");
    expect(result.refreshToken).toBe("rt-test");
    expect(result.expiresIn).toBe(3600);
    vi.unstubAllGlobals();
  });

  it("falls back to form-urlencoded when JSON fails", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce(new Response("bad", { status: 400 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: "sk-ant-oat01-form-token",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    vi.stubGlobal("fetch", mockFetch);

    const result = await exchangeClaudeOAuthCode({
      code: "auth-code",
      codeVerifier: "verifier",
    });

    expect(result.accessToken).toBe("sk-ant-oat01-form-token");
    expect(mockFetch).toHaveBeenCalledTimes(2);
    vi.unstubAllGlobals();
  });

  it("throws when both JSON and form-urlencoded fail", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce(new Response("bad", { status: 400 }))
      .mockResolvedValueOnce(new Response("also bad", { status: 500 }));
    vi.stubGlobal("fetch", mockFetch);

    await expect(
      exchangeClaudeOAuthCode({ code: "auth-code", codeVerifier: "verifier" }),
    ).rejects.toThrow("OAuth token exchange failed");
    vi.unstubAllGlobals();
  });
});

describe("refreshClaudeOAuthToken", () => {
  it("refreshes token successfully", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: "sk-ant-oat01-refreshed",
          refresh_token: "rt-new",
          expires_in: 7200,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", mockFetch);

    const result = await refreshClaudeOAuthToken("rt-old");

    expect(result.accessToken).toBe("sk-ant-oat01-refreshed");
    expect(result.refreshToken).toBe("rt-new");
    expect(result.expiresIn).toBe(7200);
    vi.unstubAllGlobals();
  });

  it("throws on refresh failure", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(new Response("unauthorized", { status: 401 }));
    vi.stubGlobal("fetch", mockFetch);

    await expect(refreshClaudeOAuthToken("rt-expired")).rejects.toThrow(
      "OAuth token refresh failed",
    );
    vi.unstubAllGlobals();
  });
});

describe("loginClaudeOAuth", () => {
  it("runs the full PKCE flow", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: "sk-ant-oat01-login-token",
          refresh_token: "rt-login",
          expires_in: 3600,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", mockFetch);

    let capturedUrl = "";
    const result = await loginClaudeOAuth({
      onAuth: async ({ url }) => {
        capturedUrl = url;
      },
      onPrompt: async () => "auth-code-from-browser",
      onProgress: () => {},
    });

    expect(capturedUrl).toContain("https://claude.ai/oauth/authorize?");
    expect(result.accessToken).toBe("sk-ant-oat01-login-token");
    expect(result.refreshToken).toBe("rt-login");
    vi.unstubAllGlobals();
  });

  it("rejects when no code is provided", async () => {
    await expect(
      loginClaudeOAuth({
        onAuth: async () => {},
        onPrompt: async () => "  ",
      }),
    ).rejects.toThrow("No authorization code provided");
  });
});

describe("createTokenReference", () => {
  it("returns prefix...hash for valid tokens", () => {
    const ref = createTokenReference("sk-ant-oat01-abcdefghij1234567890");
    // First 12 chars = "sk-ant-oat01", then "...", then 8 hex chars
    expect(ref).toMatch(/^sk-ant-oat01\.\.\.[\da-f]{8}$/);
  });

  it("returns [INVALID_TOKEN] for short tokens", () => {
    expect(createTokenReference("short")).toBe("[INVALID_TOKEN]");
    expect(createTokenReference("")).toBe("[INVALID_TOKEN]");
  });
});
