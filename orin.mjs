#!/usr/bin/env node
/**
 * orin — Orin Code command-line client.
 *
 * Authentication uses Orin Core device PKCE. Refresh credentials are kept in
 * the operating system's credential store (DPAPI on Windows, Keychain on
 * macOS, Secret Service on Linux); no bearer token is written to a JSON file.
 * The public Tools GET search route is used only for non-sensitive queries.
 */
import { createHash, randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, unlinkSync } from 'node:fs';
import { homedir, platform, userInfo } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_API = 'https://orinai.org';
const DEFAULT_TOOLS = 'https://orin-search.vercel.app';
const CLIENT_ID = 'orin-code-cli';
const SCOPES = ['chat:use', 'account:read', 'tools:use', 'code:use'];
const CREDENTIAL_SERVICE = 'orin-code-cli';
const LEGACY_FILE = join(homedir(), '.orin.json');
let memoryCredential = null;
let refreshPromise = null;

export class CliError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = 'CliError';
    this.status = status;
  }
}

export function safeOrigin(value, label = 'origin') {
  let url;
  try { url = new URL(value); } catch { throw new CliError(`${label} is invalid`); }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new CliError(`${label} must use HTTPS (or explicit localhost)`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new CliError(`${label} cannot contain credentials, query, or fragment`);
  }
  return url.origin;
}

export function createPkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export function validDeviceCode(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{40,128}$/.test(value);
}

export function validVerificationUrl(value, apiOrigin) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname))) return false;
    if (url.username || url.password) return false;
    return url.origin === safeOrigin(apiOrigin);
  } catch {
    return false;
  }
}

function accountName() {
  return process.env.ORIN_CREDENTIAL_ACCOUNT || userInfo().username || 'orin-user';
}

function runCommand(file, args, options = {}) {
  const result = spawnSync(file, args, {
    encoding: 'utf8',
    windowsHide: true,
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = String(result.stderr || '').trim();
    throw new Error(detail || `${file} exited with ${result.status}`);
  }
  return String(result.stdout || '').trim();
}

function windowsDpapiPath() {
  return join(homedir(), '.orin', 'credentials.dpapi');
}

function powershell(script, extraEnv = {}) {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return runCommand('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
    env: { ...process.env, ...extraEnv },
  });
}

function secureSet(secret) {
  const os = platform();
  if (os === 'win32') {
    const path = windowsDpapiPath();
    mkdirSync(join(homedir(), '.orin'), { recursive: true });
    powershell(
      `$ErrorActionPreference='Stop'; $s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:ORIN_SECRET_B64)); $secure=ConvertTo-SecureString -String $s; $secure | ConvertFrom-SecureString | Set-Content -LiteralPath ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:ORIN_PATH_B64))) -NoNewline`,
      { ORIN_SECRET_B64: Buffer.from(secret, 'utf8').toString('base64'), ORIN_PATH_B64: Buffer.from(path, 'utf8').toString('base64') },
    );
    return;
  }
  if (os === 'darwin') {
    runCommand('security', ['delete-generic-password', '-s', CREDENTIAL_SERVICE, '-a', accountName()]);
    runCommand('security', ['add-generic-password', '-U', '-s', CREDENTIAL_SERVICE, '-a', accountName(), '-w'], { input: secret });
    return;
  }
  if (os === 'linux') {
    runCommand('secret-tool', ['store', '--label=Orin Code CLI', 'service', CREDENTIAL_SERVICE, 'account', accountName()], { input: secret });
    return;
  }
  throw new CliError(`Secure credential storage is not supported on ${os}`);
}

function secureGet() {
  const os = platform();
  if (os === 'win32') {
    const path = windowsDpapiPath();
    if (!existsSync(path)) return null;
    const encoded = powershell(
      `$ErrorActionPreference='Stop'; $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:ORIN_PATH_B64)); $e=Get-Content -LiteralPath $p -Raw; $s=ConvertTo-SecureString $e; $b=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); try {[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR($b)))} finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)}`,
      { ORIN_PATH_B64: Buffer.from(path, 'utf8').toString('base64') },
    );
    return encoded ? Buffer.from(encoded, 'base64').toString('utf8') : null;
  }
  if (os === 'darwin') {
    try {
      return runCommand('security', ['find-generic-password', '-w', '-s', CREDENTIAL_SERVICE, '-a', accountName()]);
    } catch {
      return null;
    }
  }
  if (os === 'linux') {
    try {
      const value = runCommand('secret-tool', ['lookup', 'service', CREDENTIAL_SERVICE, 'account', accountName()]);
      return value || null;
    } catch {
      return null;
    }
  }
  throw new CliError(`Secure credential storage is not supported on ${platform()}`);
}

function secureDelete() {
  const os = platform();
  if (os === 'win32') {
    try { unlinkSync(windowsDpapiPath()); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    return;
  }
  if (os === 'darwin') {
    try { runCommand('security', ['delete-generic-password', '-s', CREDENTIAL_SERVICE, '-a', accountName()]); } catch { /* absent */ }
    return;
  }
  if (os === 'linux') {
    try { runCommand('secret-tool', ['clear', 'service', CREDENTIAL_SERVICE, 'account', accountName()]); } catch { /* absent */ }
    return;
  }
}

function envCredential() {
  const token = String(process.env.ORIN_TOKEN || '').trim();
  return token ? { accessToken: token, refreshToken: null, expiresAt: Number.POSITIVE_INFINITY, authKind: 'env' } : null;
}

function loadCredential() {
  if (memoryCredential) return memoryCredential;
  const fromEnv = envCredential();
  if (fromEnv) return fromEnv;
  const raw = secureGet();
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed.accessToken !== 'string' || !parsed.accessToken.trim()) return null;
    memoryCredential = {
      accessToken: parsed.accessToken.trim(),
      refreshToken: typeof parsed.refreshToken === 'string' ? parsed.refreshToken : null,
      expiresAt: Number(parsed.expiresAt) || 0,
      uid: parsed.uid || '',
      email: parsed.email || '',
      authKind: parsed.authKind || 'device',
    };
    return memoryCredential;
  } catch {
    throw new CliError('The stored Orin credential is invalid; run: orin logout && orin login');
  }
}

function saveCredential(credential) {
  memoryCredential = credential;
  secureSet(JSON.stringify(credential));
}

function clearCredential() {
  memoryCredential = null;
  secureDelete();
  try { unlinkSync(LEGACY_FILE); } catch (error) { if (error.code !== 'ENOENT') throw error; }
}

function apiOrigin() { return safeOrigin(process.env.ORIN_API || DEFAULT_API, 'ORIN_API'); }
function toolsOrigin() { return safeOrigin(process.env.ORIN_TOOLS || DEFAULT_TOOLS, 'ORIN_TOOLS'); }

async function refreshCredential(credential) {
  if (!credential?.refreshToken) throw new CliError('Your session expired. Run: orin login');
  if (!refreshPromise) {
    refreshPromise = request(apiOrigin(), '/api/auth/device', {
      method: 'POST', auth: false, body: { action: 'refresh', refresh_token: credential.refreshToken },
    }).then((data) => {
      if (!data.access_token || !data.refresh_token) throw new CliError('Core returned an invalid refresh response');
      const next = {
        ...credential,
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt: Date.now() + (Number(data.expires_in) || 900) * 1000,
      };
      saveCredential(next);
      return next;
    }).finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

async function accessToken() {
  const credential = loadCredential();
  if (!credential) throw new CliError('Not signed in. Run: orin login');
  if (credential.expiresAt > Date.now() + 120_000) return credential.accessToken;
  return (await refreshCredential(credential)).accessToken;
}

async function request(origin, path, { method = 'GET', body = null, auth = true, bearerOverride = null, retry = true } = {}) {
  if (!path.startsWith('/')) throw new CliError('Invalid API path');
  const token = bearerOverride || (auth ? await accessToken() : null);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000);
  try {
    const response = await fetch(origin + path, {
      method,
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        ...(body !== null ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      ...(body !== null ? { body: JSON.stringify(body) } : {}),
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401 && auth && retry && !bearerOverride) {
      memoryCredential = null;
      return request(origin, path, { method, body, auth, retry: false });
    }
    if (!response.ok) {
      const message = data?.error?.message || data?.error || data?.message || response.statusText;
      throw new CliError(`${origin}${path} failed (${response.status}): ${message}`, response.status);
    }
    return data;
  } catch (error) {
    if (error?.name === 'AbortError') throw new CliError('Orin request timed out');
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function openBrowser(rawUrl) {
  const api = apiOrigin();
  if (!validVerificationUrl(rawUrl, api)) throw new CliError('Core returned an unsafe verification URL');
  const url = new URL(rawUrl);
  const os = platform();
  const command = os === 'win32' ? 'rundll32.exe' : os === 'darwin' ? 'open' : 'xdg-open';
  const args = os === 'win32' ? ['url.dll,FileProtocolHandler', url.href] : [url.href];
  const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
  child.unref();
}

async function doLogin() {
  const { verifier, challenge } = createPkce();
  const start = await request(apiOrigin(), '/api/auth/device', {
    method: 'POST', auth: false,
    body: { action: 'start', client_id: CLIENT_ID, code_challenge: challenge, code_challenge_method: 'S256', scopes: SCOPES },
  });
  if (!validDeviceCode(start.device_code) || !validVerificationUrl(start.verification_uri, apiOrigin())) {
    throw new CliError('Core returned an invalid device authorization response');
  }
  console.log(`\nCode: ${start.user_code}\nApprove at: ${start.verification_uri}\nOpening browser…`);
  openBrowser(start.verification_uri);
  const deadline = Date.now() + (Number(start.expires_in) || 480) * 1000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, Math.max(3, Number(start.interval) || 5) * 1000));
    const token = await request(apiOrigin(), '/api/auth/device', {
      method: 'POST', auth: false,
      body: { action: 'token', client_id: CLIENT_ID, device_code: start.device_code, code_verifier: verifier },
    });
    if (token.status === 'approved') {
      const profile = await request(apiOrigin(), '/api/auth/session/introspect', { method: 'POST', body: {}, bearerOverride: token.access_token });
      saveCredential({ accessToken: token.access_token, refreshToken: token.refresh_token, expiresAt: Date.now() + (Number(token.expires_in) || 900) * 1000, uid: profile.uid || '', email: profile.email || '', authKind: 'device' });
      console.log(`Signed in as ${profile.email || profile.uid}`);
      return;
    }
    if (token.status === 'denied') throw new CliError('Sign-in was denied.');
    if (token.status === 'expired') throw new CliError('The device code expired; run: orin login');
  }
  throw new CliError('Device sign-in timed out; run: orin login');
}

function readStdin() {
  if (process.stdin.isTTY) return Promise.resolve('');
  return new Promise((resolve) => {
    let value = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { value += chunk; });
    process.stdin.on('end', () => resolve(value.trim()));
  });
}

async function doChat(rest, flags) {
  const piped = await readStdin();
  const prompt = `${rest.join(' ')}${piped ? `\n${piped}` : ''}`.trim();
  if (!prompt) throw new CliError('Give me a prompt: orin chat "hello"');
  const data = await request(apiOrigin(), '/api/chat', { method: 'POST', body: { mode: 'chat', model: flags.thinking === '1' || flags.t === '1' ? 'orin-thinking' : 'orin-balanced', prompt, history: [] } });
  console.log(data.text || '(empty)');
  if (data.searched) console.error('[searched the web]');
  for (const link of data.links || data.citations || []) console.error(`- ${link.title || link.url}: ${link.url || link.uri}`);
}

async function doSearch(rest, flags) {
  const query = rest.join(' ').trim();
  if (!query) throw new CliError('Usage: orin search "query" [-n 5]');
  const count = Math.min(Math.max(Number.parseInt(flags.n || '5', 10) || 5, 1), 10);
  const data = await request(toolsOrigin(), `/api/search?${new URLSearchParams({ q: query, n: String(count) })}`, { auth: false });
  for (const result of data.results || []) console.log(`• ${result.title}\n  ${result.url}\n  ${String(result.snippet || '').slice(0, 200)}`);
  console.error(`[${(data.engines || []).join('+') || 'none'}]`);
}

async function doRun(flags) {
  if (flags.c || flags.code || flags.f || flags.file || !process.stdin.isTTY) {
    throw new CliError('Orin Tools code execution is disabled until an Orin-controlled sandbox is available.');
  }
  throw new CliError('Usage: orin run is disabled; use a local runtime for code execution.');
}

function help() {
  console.log(`orin — Orin Code CLI\n\n  orin login                  pair this machine with Core device PKCE\n  orin chat "prompt"          ask Orin (stdin also works)\n  orin chat "prompt" --thinking\n  orin search "query" [-n 5]  public, non-sensitive web search\n  orin whoami                 show the signed-in account\n  orin logout                 remove the OS credential\n\nEnvironment: ORIN_TOKEN (development only), ORIN_API, ORIN_TOOLS`);
}

export async function main(argv = process.argv.slice(2)) {
  const cmd = argv[0];
  const flags = {};
  const rest = [];
  for (let i = 1; i < argv.length; i++) {
    const item = argv[i];
    if (item.startsWith('--')) {
      const key = item.slice(2);
      const value = argv[i + 1] && !argv[i + 1].startsWith('-') ? argv[++i] : '1';
      flags[key] = value;
    } else if (item.startsWith('-') && item.length === 2) {
      const value = argv[i + 1] && !argv[i + 1].startsWith('-') ? argv[++i] : '1';
      flags[item[1]] = value;
    } else rest.push(item);
  }
  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') return help();
  if (cmd === 'login') return doLogin();
  if (cmd === 'logout') { clearCredential(); console.log('Signed out.'); return; }
  if (cmd === 'whoami') {
    const profile = await request(apiOrigin(), '/api/auth/session/introspect', { method: 'POST', body: {} });
    console.log(`${profile.email || profile.uid} · ${profile.kind || 'session'}`);
    return;
  }
  if (cmd === 'chat') return doChat(rest, flags);
  if (cmd === 'search') return doSearch(rest, flags);
  if (cmd === 'run') return doRun(flags);
  throw new CliError(`Unknown command: ${cmd}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    console.error(error?.message || String(error));
    process.exitCode = 1;
  });
}
