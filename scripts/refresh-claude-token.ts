#!/usr/bin/env bun
import { execFileSync } from "node:child_process";
/**
 * Refresh the Claude OAuth token using a stored refresh token.
 * Writes the new access token to ~/.claude/.oauth_token
 * and updates the refresh token if rotated.
 *
 * Usage: bun scripts/refresh-claude-token.ts [--login]
 *   --login   Run the full PKCE login flow (interactive, opens browser)
 */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const TOKEN_DIR = join(homedir(), ".claude");
const ACCESS_TOKEN_PATH = join(TOKEN_DIR, ".oauth_token");
const REFRESH_TOKEN_PATH = join(TOKEN_DIR, ".oauth_refresh_token");

const CLAUDE_CODE_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token";

async function ensureDir() {
  await mkdir(TOKEN_DIR, { recursive: true });
}

async function refreshToken() {
  let refreshTok: string;
  try {
    refreshTok = (await readFile(REFRESH_TOKEN_PATH, "utf-8")).trim();
  } catch {
    console.error("No refresh token found at", REFRESH_TOKEN_PATH);
    console.error("Run with --login first to do the initial PKCE flow.");
    process.exit(1);
  }

  console.log("Refreshing Claude OAuth token...");

  const response = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      grant_type: "refresh_token",
      client_id: CLAUDE_CODE_CLIENT_ID,
      refresh_token: refreshTok,
    }),
  });

  if (!response.ok) {
    const err = await response.text().catch(() => "unknown");
    console.error(`Refresh failed: ${response.status} ${err}`);
    process.exit(1);
  }

  const data = (await response.json()) as Record<string, unknown>;
  const accessToken = data.access_token as string;
  if (!accessToken) {
    console.error("No access_token in response");
    process.exit(1);
  }

  await ensureDir();
  await writeFile(ACCESS_TOKEN_PATH, accessToken + "\n", { mode: 0o600 });
  console.log("Access token written to", ACCESS_TOKEN_PATH);

  // Update refresh token if rotated
  if (typeof data.refresh_token === "string" && data.refresh_token) {
    await writeFile(REFRESH_TOKEN_PATH, data.refresh_token + "\n", { mode: 0o600 });
    console.log("Refresh token updated.");
  }

  if (typeof data.expires_in === "number") {
    console.log(
      `Token expires in ${data.expires_in} seconds (${(data.expires_in / 3600).toFixed(1)}h)`,
    );
  }

  console.log(`\nTo use: export CLAUDE_CODE_OAUTH_TOKEN="${accessToken.slice(0, 20)}..."`);
}

async function login() {
  const { generatePkceParams, buildClaudeOAuthUrl, exchangeClaudeOAuthCode } =
    await import("../src/commands/claude-oauth-token.js");

  const pkce = generatePkceParams();
  const url = buildClaudeOAuthUrl({ codeChallenge: pkce.codeChallenge, state: pkce.state });

  console.log("\nOpen this URL in your browser:\n");
  console.log(url);
  console.log();

  // Try to open browser
  try {
    execFileSync("open", [url], { stdio: "ignore" });
  } catch {
    // ignore if open fails
  }

  // Read code from stdin
  process.stdout.write("Paste the authorization code: ");
  const reader = Bun.stdin.stream().getReader();
  const { value } = await reader.read();
  const code = new TextDecoder().decode(value).trim();
  reader.releaseLock();

  if (!code) {
    console.error("No code provided.");
    process.exit(1);
  }

  console.log("Exchanging code for token...");
  const result = await exchangeClaudeOAuthCode({
    code,
    codeVerifier: pkce.codeVerifier,
    state: pkce.state,
  });

  await ensureDir();
  await writeFile(ACCESS_TOKEN_PATH, result.accessToken + "\n", { mode: 0o600 });
  console.log("Access token written to", ACCESS_TOKEN_PATH);

  if (result.refreshToken) {
    await writeFile(REFRESH_TOKEN_PATH, result.refreshToken + "\n", { mode: 0o600 });
    console.log("Refresh token written to", REFRESH_TOKEN_PATH);
  } else {
    console.warn("Warning: no refresh token returned. Auto-refresh won't work.");
  }

  if (result.expiresIn) {
    console.log(
      `Token expires in ${result.expiresIn} seconds (${(result.expiresIn / 3600).toFixed(1)}h)`,
    );
  }

  console.log("\nDone! Token acquired successfully.");
}

const args = process.argv.slice(2);
if (args.includes("--login")) {
  await login();
} else {
  await refreshToken();
}
