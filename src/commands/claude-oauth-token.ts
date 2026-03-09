import { createHash, randomBytes } from "node:crypto";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("claude-oauth-token");

/** Claude Code's public OAuth client_id (same for all installations). */
const CLAUDE_CODE_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token";
const OAUTH_REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback";
const OAUTH_SCOPES = "org:create_api_key user:profile user:inference";

export type ClaudeOAuthResult = {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
};

/**
 * Generate PKCE parameters for Claude Code OAuth flow.
 */
export function generatePkceParams() {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  const state = randomBytes(32).toString("base64url");
  return { codeVerifier, codeChallenge, state };
}

/**
 * Build the Claude OAuth authorization URL with PKCE challenge.
 */
export function buildClaudeOAuthUrl(params: { codeChallenge: string; state: string }): string {
  const searchParams = new URLSearchParams({
    code: "true",
    client_id: CLAUDE_CODE_CLIENT_ID,
    response_type: "code",
    redirect_uri: OAUTH_REDIRECT_URI,
    scope: OAUTH_SCOPES,
    code_challenge: params.codeChallenge,
    code_challenge_method: "S256",
    state: params.state,
  });
  return `https://claude.ai/oauth/authorize?${searchParams.toString()}`;
}

/**
 * Exchange an authorization code for an access token using PKCE.
 */
export async function exchangeClaudeOAuthCode(params: {
  code: string;
  codeVerifier: string;
  state?: string;
}): Promise<ClaudeOAuthResult> {
  const body = {
    grant_type: "authorization_code",
    client_id: CLAUDE_CODE_CLIENT_ID,
    code: params.code,
    redirect_uri: OAUTH_REDIRECT_URI,
    code_verifier: params.codeVerifier,
    ...(params.state ? { state: params.state } : {}),
  };

  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
    "User-Agent":
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    Referer: "https://claude.ai/",
    Origin: "https://claude.ai",
  };

  const response = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    // Fallback: try form-urlencoded
    const formParams = new URLSearchParams();
    formParams.set("grant_type", "authorization_code");
    formParams.set("client_id", CLAUDE_CODE_CLIENT_ID);
    formParams.set("code", params.code);
    formParams.set("redirect_uri", OAUTH_REDIRECT_URI);
    formParams.set("code_verifier", params.codeVerifier);
    if (params.state) {
      formParams.set("state", params.state);
    }

    const formResponse = await fetch(OAUTH_TOKEN_URL, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
      body: formParams.toString(),
    });

    if (!formResponse.ok) {
      const errorText = await formResponse.text().catch(() => "unknown");
      throw new Error(`OAuth token exchange failed: ${formResponse.status} ${errorText}`);
    }

    const formData = (await formResponse.json()) as Record<string, unknown>;
    if (typeof formData.access_token !== "string" || !formData.access_token) {
      throw new Error("Token exchange returned no access_token");
    }
    return {
      accessToken: formData.access_token,
      refreshToken: typeof formData.refresh_token === "string" ? formData.refresh_token : undefined,
      expiresIn: typeof formData.expires_in === "number" ? formData.expires_in : undefined,
    };
  }

  const data = (await response.json()) as Record<string, unknown>;
  if (typeof data.access_token !== "string" || !data.access_token) {
    throw new Error("Token exchange returned no access_token");
  }
  return {
    accessToken: data.access_token,
    refreshToken: typeof data.refresh_token === "string" ? data.refresh_token : undefined,
    expiresIn: typeof data.expires_in === "number" ? data.expires_in : undefined,
  };
}

/**
 * Refresh a Claude OAuth token using a refresh token.
 */
export async function refreshClaudeOAuthToken(refreshToken: string): Promise<ClaudeOAuthResult> {
  const response = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      grant_type: "refresh_token",
      client_id: CLAUDE_CODE_CLIENT_ID,
      refresh_token: refreshToken,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "unknown");
    throw new Error(`OAuth token refresh failed: ${response.status} ${errorText}`);
  }

  const data = (await response.json()) as Record<string, unknown>;
  if (typeof data.access_token !== "string" || !data.access_token) {
    throw new Error("Token refresh returned no access_token");
  }

  return {
    accessToken: data.access_token,
    refreshToken: typeof data.refresh_token === "string" ? data.refresh_token : undefined,
    expiresIn: typeof data.expires_in === "number" ? data.expires_in : undefined,
  };
}

/**
 * Run `claude setup-token` as a child process and capture the generated token.
 * Falls back to PKCE OAuth if `claude` CLI is not available.
 */
export async function runClaudeSetupToken(): Promise<{
  token: string;
  authUrl?: string;
}> {
  const { spawn } = await import("node:child_process");

  return new Promise((resolve, reject) => {
    let output = "";
    let capturedToken = "";
    let capturedUrl = "";

    const child = spawn("claude", ["setup-token"], {
      env: {
        ...process.env,
        CI: "true",
        TERM: "xterm-256color",
      },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const processChunk = (chunk: string) => {
      output += chunk;

      // Capture the setup token from output
      const tokenMatch = chunk.match(/sk-ant-[a-zA-Z0-9_-]+/);
      if (tokenMatch) {
        capturedToken = tokenMatch[0];
        log.info("setup-token captured from CLI output");
      }

      // Capture auth URL
      const claudeOAuthMatch = chunk.match(/https:\/\/claude\.ai\/oauth\/[^\s\n]+/);
      const consoleMatch = chunk.match(/https:\/\/console\.anthropic\.com[^\s\]<\n]+/);
      const url = claudeOAuthMatch?.[0] ?? consoleMatch?.[0];
      if (url) {
        capturedUrl = url;
      }
    };

    child.stdout?.on("data", (data: Buffer) => processChunk(data.toString()));
    child.stderr?.on("data", (data: Buffer) => processChunk(data.toString()));

    child.on("close", (code) => {
      if (capturedToken) {
        resolve({ token: capturedToken, authUrl: capturedUrl || undefined });
      } else if (code === 0 && output.includes("sk-ant-")) {
        const finalMatch = output.match(/sk-ant-[a-zA-Z0-9_-]+/);
        if (finalMatch) {
          resolve({ token: finalMatch[0], authUrl: capturedUrl || undefined });
        } else {
          reject(new Error("setup-token completed but no token found in output"));
        }
      } else {
        reject(
          new Error(`claude setup-token exited with code ${code}. Output: ${output.slice(0, 500)}`),
        );
      }
    });

    child.on("error", (err) => {
      reject(new Error(`Failed to run claude setup-token: ${err.message}`));
    });

    // Timeout after 5 minutes
    setTimeout(
      () => {
        child.kill();
        if (capturedToken) {
          resolve({ token: capturedToken, authUrl: capturedUrl || undefined });
        } else {
          reject(new Error("claude setup-token timed out after 5 minutes"));
        }
      },
      5 * 60 * 1000,
    );
  });
}

/**
 * High-level Claude OAuth PKCE login flow.
 *
 * 1. Generate PKCE params
 * 2. Open auth URL in browser (via onAuth callback)
 * 3. Prompt user for the authorization code shown after redirect
 * 4. Exchange code for access token
 */
export async function loginClaudeOAuth(params: {
  onAuth: (event: { url: string }) => Promise<void>;
  onPrompt: (prompt: { message: string; placeholder?: string }) => Promise<string>;
  onProgress?: (message: string) => void;
}): Promise<ClaudeOAuthResult> {
  params.onProgress?.("Generating PKCE challenge…");
  const pkce = generatePkceParams();
  const url = buildClaudeOAuthUrl({
    codeChallenge: pkce.codeChallenge,
    state: pkce.state,
  });

  await params.onAuth({ url });

  params.onProgress?.("Waiting for authorization code…");
  const code = await params.onPrompt({
    message: "Paste the authorization code from the browser",
    placeholder: "code from redirect page",
  });

  const trimmedCode = code.trim();
  if (!trimmedCode) {
    throw new Error("No authorization code provided.");
  }

  params.onProgress?.("Exchanging code for token…");
  const result = await exchangeClaudeOAuthCode({
    code: trimmedCode,
    codeVerifier: pkce.codeVerifier,
    state: pkce.state,
  });

  log.info("Claude OAuth token acquired", { ref: createTokenReference(result.accessToken) });
  return result;
}

/**
 * Create a safe token reference for logging (prefix...hash).
 * Same approach as team6's LogSanitizer.createTokenReference.
 */
export function createTokenReference(token: string): string {
  if (!token || token.length < 8) {
    return "[INVALID_TOKEN]";
  }
  const prefix = token.substring(0, 12);
  const hash = createHash("sha256").update(token).digest("hex").substring(0, 8);
  return `${prefix}...${hash}`;
}
