#!/usr/bin/env node
/**
 * orin — command-line for Orin Code.
 * Zero dependencies, plain Node 18+. Never holds AI keys: chat runs on
 * orinai.org (your account), search/run on your orin-tools deployment.
 *
 *   orin login                  pair this machine (browser approves once)
 *   orin chat "prompt"          ask Orin (pipe stdin works too)
 *   orin chat "prompt" --thinking    deepest reasoning chain
 *   orin search "query" [-n 5]  web search
 *   orin run -l python -c "print(1)" | -f script.py [-i stdin]
 *   orin whoami                 show the signed-in account
 *   orin logout                 forget this machine's token
 *
 * Token lives in ~/.orin.json (0600). Env override: ORIN_TOKEN.
 */
import { readFileSync, writeFileSync, chmodSync, unlinkSync, existsSync, mkdirSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { exec } from 'node:child_process';

const API = process.env.ORIN_API || 'https://orinai.org';
const TOOLS = (process.env.ORIN_TOOLS || 'https://orin-search.vercel.app').replace(/\/+$/, '');
const HOME_CFG = join(homedir(), '.orin.json');

function loadToken() {
  if (process.env.ORIN_TOKEN) return process.env.ORIN_TOKEN.trim();
  try {
    const j = JSON.parse(readFileSync(HOME_CFG, 'utf8'));
    return (j.token || '').trim();
  } catch { return ''; }
}

function saveToken(token) {
  writeFileSync(HOME_CFG, JSON.stringify({ token, savedAt: Date.now() }) + '\n');
  try { chmodSync(HOME_CFG, 0o600); } catch {}
}

function openBrowser(url) {
  const cmd = platform() === 'win32' ? `start "" "${url}"` : platform() === 'darwin' ? `open "${url}"` : `xdg-open "${url}"`;
  exec(cmd, () => {});
}

async function api(path, { method = 'GET', body = null, auth = true } = {}) {
  const token = auth ? loadToken() : '';
  if (auth && !token) {
    console.error('Not signed in. Run: orin login');
    process.exit(2);
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 120_000);
  try {
    const r = await fetch(API + path, {
      method,
      signal: ctrl.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      console.error(`Error (${r.status}): ${j.error || r.statusText}`);
      process.exit(1);
    }
    return j;
  } finally {
    clearTimeout(timer);
  }
}

async function tools(path, { method = 'GET', body = null } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 90_000);
  try {
    const r = await fetch(TOOLS + path, {
      method,
      signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      console.error(`Error (${r.status}): ${j.error || r.statusText}`);
      process.exit(1);
    }
    return j;
  } finally {
    clearTimeout(timer);
  }
}

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    let s = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { s += c; });
    process.stdin.on('end', () => resolve(s.trim()));
  });
}

const args = process.argv.slice(2);
const cmd = args[0];
const flags = {};
const rest = [];
for (let i = 1; i < args.length; i++) {
  const a = args[i];
  if (a.startsWith('--')) {
    const k = a.slice(2);
    const v = args[i + 1] && !args[i + 1].startsWith('-') ? args[++i] : '1';
    flags[k] = v;
  } else if (a.startsWith('-') && a.length === 2) {
    const v = args[i + 1] && !args[i + 1].startsWith('-') ? args[++i] : '1';
    flags[a[1]] = v;
  } else {
    rest.push(a);
  }
}

function help() {
  console.log(`orin — command-line for Orin Code

  orin login                  pair this machine (browser approves once)
  orin chat "prompt"          ask Orin (stdin also works: echo hi | orin chat)
  orin chat "prompt" --thinking
  orin search "query" [-n 5]  web search
  orin run -l python (-c CODE | -f FILE) [-i STDIN]
  orin whoami                 signed-in account
  orin logout                 forget this machine

env: ORIN_TOKEN (skip file), ORIN_API, ORIN_TOOLS`);
}

async function doLogin() {
  const s = await api('/api/auth/device', { method: 'POST', body: { action: 'start' }, auth: false });
  console.log(`\nCode: ${s.user_code}\nApprove at: ${s.verify_url}\nOpening browser… (waiting up to 10 min)\n`);
  openBrowser(s.verify_url);
  const deadline = Date.now() + (s.expires_in || 600) * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, (s.interval || 3) * 1000));
    const t = await api('/api/auth/device', { method: 'POST', body: { action: 'token', device_code: s.device_code }, auth: false });
    if (t.status === 'approved' && (t.session_token || t.custom_token)) {
      saveToken(t.session_token || t.custom_token);
      const me = await api('/api/me', { method: 'POST', body: { action: 'sync' } });
      console.log(`Signed in as ${me.name || me.email} (${me.email || 'no email'})`);
      return;
    }
    if (t.status === 'denied') { console.error('Denied.'); process.exit(1); }
    if (t.status === 'expired') { console.error('Code expired — run orin login again.'); process.exit(1); }
  }
  console.error('Timed out — run orin login again.');
  process.exit(1);
}

async function doChat() {
  const piped = await readStdin();
  const prompt = (rest.join(' ') + (piped ? '\n' + piped : '')).trim();
  if (!prompt) { console.error('Give me a prompt: orin chat "hello"'); process.exit(1); }
  const j = await api('/api/chat', {
    method: 'POST',
    body: { prompt, thinking: flags.thinking === '1' || flags.t === '1' },
  });
  console.log(j.text || '(empty)');
  if (j.searched) console.error('[searched the web]');
  for (const l of j.links || []) console.error(`- ${l.title || l.uri}: ${l.uri}`);
}

async function doSearch() {
  const q = rest.join(' ').trim();
  if (!q) { console.error('Usage: orin search "query" [-n 5]'); process.exit(1); }
  const n = Math.min(Math.max(parseInt(flags.n || '5', 10) || 5, 1), 10);
  const j = await tools(`/api/search?${new URLSearchParams({ q, n: String(n) })}`);
  for (const r of j.results || []) {
    console.log(`• ${r.title}\n  ${r.url}\n  ${(r.snippet || '').slice(0, 200)}`);
  }
  console.error(`[${(j.engines || []).join('+') || 'none'} · $0.00]`);
}

async function doRun() {
  const lang = flags.l || flags.language;
  let code = flags.c || flags.code || '';
  if (flags.f || flags.file) {
    try { code = readFileSync(flags.f || flags.file, 'utf8'); }
    catch { console.error('Cannot read file.'); process.exit(1); }
  }
  if (!code && !process.stdin.isTTY) code = await readStdin();
  if (!lang || !code) { console.error('Usage: orin run -l python (-c CODE | -f FILE | stdin)'); process.exit(1); }
  const j = await tools('/api/run', { method: 'POST', body: { language: lang, code, stdin: flags.i || flags.stdin || '' } });
  if (j.output) console.log(j.output);
  console.error(`[${j.language} ${j.version} · exit ${j.code} · $0.00]`);
}

async function main() {
  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') return help();
  if (cmd === 'login') return doLogin();
  if (cmd === 'logout') {
    try { unlinkSync(HOME_CFG); } catch {}
    console.log('Signed out.');
    return;
  }
  if (cmd === 'whoami') {
    const me = await api('/api/me', { method: 'POST', body: { action: 'sync' } });
    console.log(`${me.name || '?'} <${me.email || '?'}> · ${me.plan || 'free'} · ${me.role || 'visitor'}`);
    return;
  }
  if (cmd === 'chat') return doChat();
  if (cmd === 'search') return doSearch();
  if (cmd === 'run') return doRun();
  console.error(`Unknown command: ${cmd}`);
  help();
  process.exit(1);
}

main().catch((e) => { console.error(e.message || e); process.exit(1); });
