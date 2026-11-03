#!/usr/bin/env bun

import { Database } from 'bun:sqlite';
import { spawnSync, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync, copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readSync,
  readdirSync, realpathSync, renameSync, rmSync, statSync, statfsSync, writeFileSync,
} from 'node:fs';
import { realpath as realpathP, stat as statP } from 'node:fs/promises';
import { homedir, hostname, platform as osPlatform, release as osRelease, arch as osArch, userInfo, cpus, totalmem } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import vm from 'node:vm';

const DOCTOR_VERSION = '1.0.0';
const BUILT_FOR = '0.0.198';
const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const API_HOST = 'https://www.codebuff.com';

const HELP = `Freebuff Repair Tool ${DOCTOR_VERSION}

Usage: frt [options]

  (no options)            Scan everything (read-only), write a Markdown report, then offer repairs.
  --ui                    Open the one-click window (progress bar, repair, copy/open report).
  --fix                   Offer each available repair (asks before each one).
  --yes                   With --fix: apply every low-risk repair without asking.
  --yes-all               With --fix: apply every repair without asking, including the ones marked
                          "confirm" (database rebuild, computer-ID restore, Git safe.directory).
  --deep                  Slower checks: full SQLite integrity_check, hash every key install file,
                          measure worktree sizes.
  --error "<message>"     Explain a Freebuff error message and focus the report on it.
  --offline               Make no network requests.
  --out <folder>          Where to write the report (default: current folder).
  --json                  Also write the findings as JSON.
  --no-redact             Keep full paths, user name and e-mail in the report.
  --hide-titles           Leave chat titles out of the report.
  --state <state.json>    Use a different Freebuff profile (default: ~/.config/freebuff-desktop/state.json
                          or $FREEBUFF_DESKTOP_STATE_PATH).
  --install <folder>      Freebuff's installation folder, if it is not found automatically.
  --restore <backup dir>  Undo the repairs recorded in a backup folder.
  --no-open               Do not open the report when finished (Windows).
  --help                  Show this help.

Exit code: 0 = no errors found, 1 = errors found, 2 = the repair tool itself failed.`;

function parseArgs(argv) {
  const o = { fix: false, yes: false, deep: false, offline: false, json: false, redact: true, hideTitles: false, open: true, errors: [] };
  const takes = new Set(['--error', '--out', '--state', '--install', '--restore']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    let v;
    if (takes.has(a)) { v = argv[++i]; if (v === undefined) die(`Missing value for ${a}`); }
    switch (a) {
      case '--fix': o.fix = true; break;
      case '--yes': case '-y': o.yes = true; break;
      case '--yes-all': o.yes = true; o.yesAll = true; break;
      case '--deep': o.deep = true; break;
      case '--offline': o.offline = true; break;
      case '--json': o.json = true; break;
      case '--no-redact': o.redact = false; break;
      case '--hide-titles': o.hideTitles = true; break;
      case '--no-open': o.open = false; break;
      case '--ui': o.ui = true; break;
      case '--error': o.errors.push(v); break;
      case '--out': o.out = v; break;
      case '--state': o.state = v; break;
      case '--install': o.install = v; break;
      case '--restore': o.restore = v; break;
      case '--help': case '-h': case '/?': console.log(HELP); process.exit(0);
      default: die(`Unknown option ${a}\n\n${HELP}`);
    }
  }
  return o;
}
function die(message) { console.error(message); process.exit(2); }

const RELEASE_MANIFESTS = {
  '0.0.198': {
    platform: 'win32', commit: '8b37ede6513393202ec7fc72bc1b4c724843a78f', totalFiles: 5914,
    dirs: {
      '.': { files: 16, bytes: 238791279, digest: '8e5647e1471f1f1584b82f90a3ef14e5' },
      'locales': { files: 55, bytes: 42207130, digest: 'f86c5a884b41370777739eb916ef3431' },
      'resources': { files: 4, bytes: 30255955, digest: 'a7f8a3617cadbb2c5c5e159a4a2e8238' },
      'resources/bun': { files: 2, bytes: 172204552, digest: 'eb4903f57ba5e873afd778b73e1bad94' },
      'resources/git': { files: 5735, bytes: 368718657, digest: 'd6ae60967bd2a5be5884047ca8594071' },
      'resources/orchestrator': { files: 102, bytes: 38014611, digest: '39af16771371147417afafa581de4095' },
    },
    hashes: null,
  },
};
const RELEASE_HASHES_198 = {"Freebuff.exe":{"size":188826888,"sha256":"cf32014bfc476f90bceb84e5f31a03c260a4924200eb0aaaf3dd54c705dda21a"},"resources/app.asar":{"size":29595578,"sha256":"9f3f2b86cb5b099f82d9b13692027bb5240d3c286dd3293d648c18fcb97f8e5b"},"resources/orchestrator/orchestrator.js":{"size":9440040,"sha256":"ad3486baede63745c7862328f2b7c1a1eeb203df6de0b26f9c54da4f6924d5c0"},"resources/bun/bun.exe":{"size":86102280,"sha256":"0ebaf1c8853167b47d7b101b920e47703316123ffc64e081dff24b685cfea376"},"resources/bun/bun-baseline.exe":{"size":86102272,"sha256":"880d6b21c4bae7d696d8020d8530f7156d78fb7ec3b7a4f21689699a649c8045"},"resources/git/cmd/git.exe":{"size":47000,"sha256":"dd83f50fbf5c08da85d178d3254d0f47ca7e2d7ef4bbd02351982d865a037a53"},"resources/orchestrator/windows-command.exe":{"size":170752,"sha256":"ffcc5ef06810934173bade159bf08a18986ea2f78a86e563be126b3fc8c246b5"},"resources/orchestrator/claude-elevation-hook.js":{"size":4432,"sha256":"32f7ce0c588351e2d9a750dea1d618ba0298e6eff35a5fc83997b2eca4811480"},"resources/elevate.exe":{"size":123144,"sha256":"be034d7a9dc0f0f8c53f6468b7904fd574610f8365a714dd8a8dd2c50d82c221"},"resources/electron-updater.cjs":{"size":537070,"sha256":"2cc106a80bfd572acd98ed4fad4d79e045a08590a0b09952eb4afe24ce6bfa60"},"resources/orchestrator/build-info.json":{"size":56,"sha256":"107c5779c82d7bbe015ce27987b4af32c7e37f5637fd355565b5b1096c81d006"},"resources/app-update.yml":{"size":163,"sha256":"e01db0c14b3c5ed009a026b8fbfdfbbfe7924f59a5fc3259393981c78814288e"}};
RELEASE_MANIFESTS['0.0.198'].hashes = RELEASE_HASHES_198;

const SCHEMA_OBJECTS = ['freebuff_storage_metadata', 'projects', 'threads', 'idx_threads_project', 'messages',
  'idx_messages_thread', 'idx_messages_request', 'idx_messages_input', 'freebuff_conversation_search',
  'freebuff_conversation_search_insert', 'freebuff_conversation_search_delete', 'freebuff_conversation_search_update',
  'queue_items', 'idx_queue_thread_state', 'idx_inputs_thread_delivery', 'auto_run_decision_receipts',
  'idx_auto_run_receipts_thread', 'idx_auto_run_receipts_queue_item', 'sponsored_runs', 'idx_sponsored_runs_thread',
  'idx_sponsored_runs_unsettled', 'thread_deliveries', 'idx_thread_deliveries_thread', 'idx_thread_deliveries_pr_url',
  'idx_thread_deliveries_local_head', 'thread_handoff_bases', 'thread_landing_conflicts'];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PROJECT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DB_FILENAME = 'desktop-v2.db';

const embeddedIdentity = {
  deviceIdentity: (hex) => `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`,
  async deviceFolderIdentity(path) {
    const canonicalPath = await realpathP(path);
    const s = await statP(canonicalPath, { bigint: true });
    if (!s.isDirectory()) throw new Error('Local folder is unavailable');
    return { path: canonicalPath, dev: s.dev.toString(), ino: s.ino.toString() };
  },
  deviceFolderBinding(apiHost, accountId, installId, folder) {
    const part = (id) => { const n = Number(id); return Number.isSafeInteger(n) ? n : id; };
    return embeddedIdentity.deviceIdentity(createHash('sha256').update(JSON.stringify([apiHost, accountId, installId, folder.path, part(folder.dev), part(folder.ino)])).digest('hex'));
  },
};
function sessionIdFor(identity, accountId, installId, bindingId) {
  return identity.deviceIdentity(createHash('sha256').update(JSON.stringify([accountId, installId, bindingId])).digest('hex'));
}
function loadBundleIdentity(bundlePath) {
  const src = readFileSync(bundlePath, 'utf8');
  const a = src.match(/function deviceIdentity\(\w+\) \{\n[\s\S]*?\n\}\n/);
  const b = src.match(/async function deviceFolderIdentity\([\s\S]*?\nfunction deviceFolderBinding\([\s\S]*?\n\}\n/);
  if (!a || !b) throw new Error('identity functions not found in this build');
  const code = a[0] + b[0];
  const ctx = {};
  for (const name of new Set(code.match(/\b(?:createHash|realpath|stat)\d*\b/g) ?? [])) {
    ctx[name] = name.startsWith('createHash') ? createHash : name.startsWith('realpath') ? realpathP : statP;
  }
  return vm.runInNewContext(`${code}\n({ deviceIdentity, deviceFolderIdentity, deviceFolderBinding })`, ctx, { filename: 'installed-device-identity.js' });
}

function sh(cmd, args, opts = {}) {
  try {
    const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: opts.timeout ?? 20000, windowsHide: true, maxBuffer: 32 * 1024 * 1024, ...opts });
    return { ok: r.status === 0 && !r.error, code: r.status, stdout: (r.stdout ?? '').trim(), stderr: (r.stderr ?? '').trim(), error: r.error?.message };
  } catch (e) { return { ok: false, code: null, stdout: '', stderr: '', error: e.message }; }
}
const statSafe = (p) => { try { return statSync(p); } catch { return null; } };
const lstatSafe = (p) => { try { return lstatSync(p); } catch { return null; } };
const isDir = (p) => !!statSafe(p)?.isDirectory();
const isFile = (p) => !!statSafe(p)?.isFile();
const readText = (p) => { try { return readFileSync(p, 'utf8'); } catch { return null; } };
const listDir = (p) => { try { return readdirSync(p, { withFileTypes: true }); } catch { return []; } };
function readJson(p) {
  let text;
  try { text = readFileSync(p, 'utf8'); } catch (e) { return { status: e.code === 'ENOENT' ? 'missing' : 'unreadable', error: e.code ?? e.message }; }
  try { return { status: 'ok', value: JSON.parse(text), bytes: Buffer.byteLength(text) }; } catch (e) { return { status: 'corrupt', error: e.message, bytes: Buffer.byteLength(text), text }; }
}
function sha256File(p) {
  const h = createHash('sha256'); const fd = openSync(p, 'r'); const buf = Buffer.allocUnsafe(4 << 20);
  try { let n; while ((n = readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n)); } finally { closeSync(fd); }
  return h.digest('hex');
}
function fmtBytes(n) {
  if (n == null || !Number.isFinite(Number(n))) return '?';
  n = Number(n); const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function ago(ms) {
  if (!ms) return 'unknown';
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 0) return 'in the future (clock skew?)';
  if (s < 90) return `${s}s ago`; if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`; return `${Math.round(s / 86400)} days ago`;
}
const iso = (ms) => (ms ? new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '—');
const sha = (v) => createHash('sha256').update(v).digest('hex');
const short = (id) => (id ? String(id).slice(0, 8) : '—');
const samePathish = (a, b) => (IS_WIN ? String(a).toLowerCase() === String(b).toLowerCase() : a === b);
function canonical(p) { try { return realpathSync.native(p); } catch { return resolve(p); } }
function normPath(p) {
  let s = String(p).trim();
  if (IS_WIN) { if (s.startsWith('\\\\?\\UNC\\')) s = `\\\\${s.slice(8)}`; else if (s.startsWith('\\\\?\\')) s = s.slice(4); s = s.replace(/\\/g, '/').toLowerCase(); }
  return s.length > 1 && s.endsWith('/') && !s.endsWith(':/') ? s.slice(0, -1) : s;
}
const samePath = (a, b) => normPath(canonical(a)) === normPath(canonical(b));
function within(child, parent) { const r = relative(resolve(parent), resolve(child)); return r === '' || (!r.startsWith('..') && !isAbsolute(r)); }
function mdEscape(s) { return String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' '); }
function truncate(s, n) { s = String(s ?? ''); return s.length > n ? `${s.slice(0, n - 1)}…` : s; }
function tailFile(p, bytes) {
  const s = statSafe(p); if (!s) return null;
  const fd = openSync(p, 'r'); const len = Math.min(bytes, s.size); const buf = Buffer.alloc(len);
  try { readSync(fd, buf, 0, len, s.size - len); } finally { closeSync(fd); }
  return buf.toString('utf8');
}
function renameRetry(from, to) {
  const waits = [50, 100, 200, 400, 800, 1200, 2000];
  for (let i = 0; ; i++) {
    try { return renameSync(from, to); } catch (e) {
      if (!['EPERM', 'EBUSY', 'EACCES', 'ENOTEMPTY'].includes(e.code) || i >= waits.length) throw e;
      Bun.sleepSync(waits[i]);
    }
  }
}
function dirStats(p, limit = 200000) {
  let files = 0, bytes = 0, truncated = false;
  (function walk(d) { for (const e of listDir(d)) { if (files >= limit) { truncated = true; return; } const q = join(d, e.name); if (e.isDirectory()) walk(q); else if (e.isFile()) { files++; bytes += statSafe(q)?.size ?? 0; } } })(p);
  return { files, bytes, truncated };
}

function openDb(path, options) {
  const db = new Database(path, options);
  const live = [];
  const prepare = db.prepare.bind(db), close = db.close.bind(db);
  db.query = db.prepare = (sql) => { const s = prepare(sql); live.push(s); return s; };
  db.close = () => { for (const s of live.splice(0)) { try { s.finalize(); } catch {} } return close(); };
  return db;
}

function termProgress() {
  const out = process.stdout;
  if (!out.isTTY) return { update() {}, stop(msg) { if (msg) console.log(msg); } };
  const frames = IS_WIN ? ['|', '/', '-', '\\'] : ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  const color = (c, s) => (process.env.NO_COLOR ? s : `\x1b[${c}m${s}\x1b[0m`);
  let f = 0, target = 0, shown = 0, label = '', title = 'Scanning', timer = null, pulse = 0;
  const draw = () => {
    shown += (target - shown) * 0.3; if (Math.abs(target - shown) < 0.003) shown = target;
    const cols = (out.columns || 80) - 1, w = Math.max(10, Math.min(36, cols - 48));
    const n = Math.round(shown * w); pulse = (pulse + 1) % Math.max(1, w);
    let bar = '█'.repeat(n) + '░'.repeat(w - n);
    if (n < w && target < 1) bar = bar.slice(0, n) + '▒' + bar.slice(n + 1);
    const pct = String(Math.round(shown * 100)).padStart(3) + '%';
    const line = `${color(36, frames[f++ % frames.length])} ${title.padEnd(10)} ${color(34, bar)} ${pct}  ${label}`;
    out.write('\r' + line.slice(0, cols + 20).padEnd(cols) + '\x1b[K');
  };
  return {
    update(p, l, t) { target = Math.max(0, Math.min(1, p)); if (l !== undefined) label = l; if (t) title = t; draw(); if (!timer) timer = setInterval(draw, 90); },
    stop(msg) { if (timer) { clearInterval(timer); timer = null; target = shown = 1; label = 'done'; draw(); out.write('\n'); } if (msg) console.log(msg); },
  };
}

const SEVERITY = { error: 0, warn: 1, info: 2, ok: 3 };
const ICON = { error: '❌', warn: '⚠️', info: 'ℹ️', ok: '✅' };
const TAG = { error: '[ERROR]', warn: '[WARN] ', info: '[INFO] ', ok: '[OK]   ' };

class Scan {
  constructor() { this.findings = []; this.inventory = {}; this.fixes = []; this.notes = []; this.timings = {}; }
  add(f) {
    const finding = { severity: 'info', area: 'General', evidence: [], steps: [], ...f };
    finding.key = finding.key ?? `${finding.area}:${finding.title}`;
    if (finding.fix) { finding.fix.findingKey = finding.key; this.fixes.push(finding.fix); }
    this.findings.push(finding); return finding;
  }
  ok(area, title, detail) { return this.add({ severity: 'ok', area, title, detail }); }
  count(sev) { return this.findings.filter((f) => f.severity === sev).length; }
}

function discoverPaths(opts) {
  const home = homedir();
  const envState = process.env.FREEBUFF_DESKTOP_STATE_PATH?.trim();
  const realState = join(home, '.config', 'freebuff-desktop', 'state.json');
  const statePath = resolve(opts.state ?? (envState || realState));
  const appData = process.env.APPDATA ?? join(home, 'AppData', 'Roaming');
  const localAppData = process.env.LOCALAPPDATA ?? join(home, 'AppData', 'Local');
  const userData = IS_WIN ? join(appData, 'Freebuff') : IS_MAC ? join(home, 'Library', 'Application Support', 'Freebuff') : join(process.env.XDG_CONFIG_HOME ?? join(home, '.config'), 'Freebuff');
  const logsDir = IS_MAC ? join(home, 'Library', 'Logs', 'Freebuff') : join(userData, 'logs');
  return {
    home, statePath, realState, envState, isRealProfile: resolve(statePath) === resolve(realState),
    profileDir: dirname(statePath), userData, logsDir, appData, localAppData,
    worktreesDir: join(home, '.freebuff', 'worktrees'),
    updaterCache: IS_WIN ? join(localAppData, '@codebufffreebuff-desktop-updater') : IS_MAC ? join(home, 'Library', 'Caches', '@codebufffreebuff-desktop-updater') : join(home, '.cache', '@codebufffreebuff-desktop-updater'),
    byokDir: process.env.FREEBUFF_BYOK_CONFIG_DIR ?? join(home, '.config', 'freebuff', 'byok'),
  };
}

function installCandidates(opts, P) {
  const out = [];
  const push = (dir, how) => { if (dir && !out.some((c) => samePathish(resolve(c.dir), resolve(dir)))) out.push({ dir: resolve(dir), how }); };
  if (opts.install) push(opts.install, '--install option');
  const exe = process.execPath;
  if (/[\\/]resources[\\/]bun[\\/]bun(-baseline)?(\.exe)?$/i.test(exe)) push(dirname(dirname(dirname(exe))), 'the Bun running this tool');
  if (IS_WIN) {
    const r = sh('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Freebuff*' } | ForEach-Object { [pscustomobject]@{ Name=$_.DisplayName; Version=$_.DisplayVersion; Location=$_.InstallLocation; Uninstall=$_.UninstallString } } | ConvertTo-Json -Compress"]);
    let entries = [];
    try { const v = JSON.parse(r.stdout || '[]'); entries = Array.isArray(v) ? v : [v]; } catch {}
    for (const e of entries) {
      const loc = e.Location || (e.Uninstall ? dirname(String(e.Uninstall).replace(/^"|"(\s.*)?$/g, '').replace(/"/g, '')) : null);
      if (loc) push(loc, `Windows "Installed apps" entry (${e.Name ?? 'Freebuff'} ${e.Version ?? ''})`.trim());
    }
    for (const name of ['Freebuff', 'freebuff-desktop', '@codebufffreebuff-desktop']) push(join(P.localAppData, 'Programs', name), 'standard per-user location');
    if (process.env.ProgramFiles) push(join(process.env.ProgramFiles, 'Freebuff'), 'standard per-machine location');
  } else if (IS_MAC) {
    push('/Applications/Freebuff.app/Contents', 'standard location');
    push(join(P.home, 'Applications', 'Freebuff.app', 'Contents'), 'per-user Applications');
  } else {
    for (const d of ['/opt/Freebuff', '/opt/freebuff', '/usr/lib/freebuff', join(P.home, '.local', 'opt', 'freebuff')]) push(d, 'common location');
    for (const e of listDir(join(P.home, '.local', 'opt'))) if (/freebuff/i.test(e.name)) push(join(P.home, '.local', 'opt', e.name), 'common location');
  }
  return out;
}
function resourcesOf(dir) { return isDir(join(dir, 'Resources')) && !isDir(join(dir, 'resources')) ? join(dir, 'Resources') : join(dir, 'resources'); }

function readAsarPackage(asarPath) {
  const fd = openSync(asarPath, 'r');
  try {
    const head = Buffer.alloc(16); readSync(fd, head, 0, 16, 0);
    const jsonLen = head.readUInt32LE(12); if (jsonLen <= 0 || jsonLen > 64 << 20) throw new Error('bad asar header');
    const hb = Buffer.alloc(jsonLen); readSync(fd, hb, 0, jsonLen, 16);
    const header = JSON.parse(hb.toString('utf8')); const entry = header.files?.['package.json'];
    if (!entry || entry.unpacked) throw new Error('package.json not in archive');
    const buf = Buffer.alloc(entry.size); readSync(fd, buf, 0, entry.size, 8 + head.readUInt32LE(4) + Number(entry.offset));
    return JSON.parse(buf.toString('utf8'));
  } finally { closeSync(fd); }
}

function runningProcesses() {
  const list = [];
  if (IS_WIN) {
    const r = sh('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      "Get-CimInstance Win32_Process -Filter \"Name='Freebuff.exe' OR Name='bun.exe' OR Name='bun-baseline.exe' OR Name='git.exe'\" | Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"], { timeout: 30000 });
    let rows = [];
    try { const v = JSON.parse(r.stdout || '[]'); rows = Array.isArray(v) ? v : [v]; } catch {}
    if (!rows.length && !r.ok) {
      const t = sh('tasklist', ['/FO', 'CSV', '/NH']);
      for (const line of t.stdout.split(/\r?\n/)) { const m = line.match(/^"([^"]+)","(\d+)"/); if (m && /^(freebuff|bun|bun-baseline|git)\.exe$/i.test(m[1])) rows.push({ Name: m[1], ProcessId: Number(m[2]) }); }
    }
    for (const p of rows) {
      const cmd = p.CommandLine ?? '';
      const kind = /^freebuff\.exe$/i.test(p.Name) ? 'app' : /^git\.exe$/i.test(p.Name) ? 'git' : /orchestrator\.js/i.test(cmd) ? 'orchestrator' : 'bun';
      list.push({ pid: p.ProcessId, kind, exe: p.ExecutablePath ?? p.Name, cmd });
    }
  } else {
    const r = sh('ps', ['-axo', 'pid=,args=']);
    for (const line of r.stdout.split('\n')) {
      const m = line.trim().match(/^(\d+)\s+(.*)$/); if (!m || Number(m[1]) === process.pid) continue;
      const cmd = m[2];
      if (/frt\.mjs/i.test(cmd)) continue;
      const kind = /orchestrator\.js/.test(cmd) ? 'orchestrator' : /[\\/](Freebuff|freebuff)( |$)|Freebuff\.app\/Contents\/MacOS\/Freebuff(?! Helper)/.test(cmd) ? 'app' : /(^|\/)git( |$)/.test(cmd) ? 'git' : null;
      if (kind) list.push({ pid: Number(m[1]), kind, exe: cmd.split(' ')[0], cmd });
    }
  }
  return list;
}
function appBlocks(lock, procs, install) {
  if (lock.state === 'held') return true;
  const live = procs.filter((p) => p.kind === 'app' || p.kind === 'orchestrator');
  if (lock.state !== 'free') return live.length > 0;
  return live.some((p) => !install || !isAbsolute(p.exe ?? '') || within(p.exe, install.dir));
}
function lockPathFor(statePath) { return `${statePath}.orchestrator-lock.sqlite`; }
function profileLockState(statePath) {
  const p = lockPathFor(statePath);
  if (!existsSync(p)) return { state: 'absent', path: p };
  let db;
  try {
    db = openDb(p, { readwrite: true, create: false });
    db.exec('PRAGMA busy_timeout = 0'); db.exec('BEGIN EXCLUSIVE'); db.exec('ROLLBACK');
    return { state: 'free', path: p };
  } catch (e) {
    return /busy|locked/i.test(`${e.code} ${e.message}`) ? { state: 'held', path: p } : { state: 'error', path: p, error: e.message };
  } finally { try { db?.close(); } catch {} }
}
function holdProfileLock(statePath) {
  const p = lockPathFor(statePath);
  mkdirSync(dirname(p), { recursive: true });
  const db = openDb(p, { create: true });
  db.exec('PRAGMA busy_timeout = 0'); db.exec('CREATE TABLE IF NOT EXISTS ownership (singleton INTEGER PRIMARY KEY)'); db.exec('BEGIN EXCLUSIVE');
  return () => { try { db.exec('ROLLBACK'); } catch {} try { db.close(); } catch {} };
}

function makeGit(installRes) {
  const bundled = installRes && [join(installRes, 'git', 'cmd', 'git.exe'), join(installRes, 'git', 'bin', 'git')].find(isFile);
  const exe = bundled ?? 'git';
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C' };
  const run = (cwd, args, timeout = 20000) => sh(exe, ['-C', cwd, ...args], { env, timeout });
  return { exe, bundled: !!bundled, run };
}

async function scan(opts, P, onProgress = () => {}) {
  const S = new Scan();
  const t0 = Date.now();
  const total = 21 + (opts.offline ? 0 : 1) + opts.errors.length;
  let done = 0;
  const step = async (name, fn) => {
    onProgress({ step: name, done: done++, total });
    await new Promise((r) => setTimeout(r, 30));
    const s = Date.now();
    try { await fn(); } catch (e) {
      S.add({ severity: 'warn', area: 'Doctor', title: `The "${name}" check could not finish`, detail: `${e?.message ?? e}`, evidence: [String(e?.stack ?? '').split('\n').slice(0, 4).join(' | ')], steps: ['This is a limitation of the repair tool, not necessarily a Freebuff problem. Include this report when contacting support.'] });
    }
    S.timings[name] = Date.now() - s;
  };
  const ctx = { P, opts, S };

  await step('environment', () => checkEnvironment(ctx));
  await step('installation', () => checkInstallation(ctx));
  await step('running processes', () => checkProcesses(ctx));
  await step('identity functions', () => checkIdentityFunctions(ctx));
  await step('profile', () => checkProfile(ctx));
  await step('sign-in', () => checkAuth(ctx));
  await step('projects', () => checkProjects(ctx));
  await step('chat databases', () => checkDatabases(ctx));
  await step('folder approvals', () => checkGrants(ctx));
  await step('worktrees', () => checkWorktrees(ctx));
  await step('chats', () => checkThreads(ctx));
  await step('chat folders', () => checkThreadDirs(ctx));
  await step('local vs cloud', () => checkCloudRouting(ctx));
  await step('skills', () => checkSkills(ctx));
  await step('credits', () => checkRefunds(ctx));
  await step('git repositories', () => checkGit(ctx));
  await step('pending transfers', () => checkJournals(ctx));
  await step('disk and filesystems', () => checkDisks(ctx));
  await step('logs', () => checkLogs(ctx));
  await step('crash reports', () => checkCrashes(ctx));
  await step('interface', () => checkInterface(ctx));
  if (!opts.offline) await step('network', () => checkNetwork(ctx));
  for (const e of opts.errors) await step('error lookup', () => explainError(ctx, e));
  S.elapsedMs = Date.now() - t0;
  S.ctx = ctx;
  return S;
}

function checkEnvironment({ P, S, opts }) {
  const area = 'Environment';
  const u = (() => { try { return userInfo().username; } catch { return process.env.USERNAME ?? process.env.USER ?? '?'; } })();
  let winBuild = null;
  if (IS_WIN) { const r = sh('cmd.exe', ['/d', '/c', 'ver']); winBuild = r.stdout.replace(/\s+/g, ' ').trim(); }
  S.inventory.environment = {
    os: `${osPlatform()} ${osRelease()} ${osArch()}${winBuild ? ` (${winBuild})` : ''}`,
    cpu: `${cpus()[0]?.model ?? '?'} × ${cpus().length}`, memory: fmtBytes(totalmem()), host: opts.redact ? '<host>' : hostname(), user: opts.redact ? '<user>' : u,
    home: P.home, doctorRuntime: `Bun ${process.versions.bun ?? '?'} at ${process.execPath}`,
  };
  const vars = ['FREEBUFF_DESKTOP_STATE_PATH', 'FREEBUFF_BUN_PATH', 'FREEBUFF_DISABLE_UPDATE_CHECK', 'FREEBUFF_AUTH_HOST', 'FREEBUFF_CONVEX_URL', 'FREEBUFF_BYOK_CONFIG_DIR', 'FREEBUFF_MCP_DISABLED', 'FREEBUFF_PROFILE_LOCK_WAIT_MS', 'NEXT_PUBLIC_CODEBUFF_APP_URL', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED'];
  const set = vars.filter((v) => process.env[v] !== undefined || process.env[v.toLowerCase()] !== undefined);
  S.inventory.environment.variables = Object.fromEntries(set.map((v) => [v, /TOKEN|KEY|SECRET/.test(v) ? '(set)' : process.env[v] ?? process.env[v.toLowerCase()]]));
  if (P.envState) {
    S.add({ severity: P.isRealProfile ? 'info' : 'warn', area, title: 'FREEBUFF_DESKTOP_STATE_PATH is set',
      detail: P.isRealProfile ? 'It points at the normal profile, so it has no effect.' : `Freebuff will use a different profile (${P.statePath}) instead of the normal one (${P.realState}). Chats, projects and sign-in in the normal profile will look missing.`,
      steps: P.isRealProfile ? [] : ['If you did not set this on purpose, remove it: Windows Settings → System → About → Advanced system settings → Environment Variables → delete FREEBUFF_DESKTOP_STATE_PATH, then sign out of Windows and back in.', 'Run the repair tool again afterwards.'] });
  }
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') S.add({ severity: 'warn', area, title: 'TLS certificate checking is disabled for Node/Bun programs', detail: 'NODE_TLS_REJECT_UNAUTHORIZED=0 is set in your environment. It is unsafe and can mask proxy problems.', steps: ['Remove the NODE_TLS_REJECT_UNAUTHORIZED environment variable unless your IT department requires it.'] });
  if (/[^\x00-\x7f]/.test(P.home)) S.add({ severity: 'info', area, title: 'Your home folder path contains non-ASCII characters', detail: `Some developer tools (older Git hooks, some build tools) mishandle such paths. Freebuff itself supports them.`, evidence: [P.home] });
  if (IS_WIN) {
    const r = sh('reg', ['query', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem', '/v', 'LongPathsEnabled']);
    const on = /LongPathsEnabled\s+REG_DWORD\s+0x1/i.test(r.stdout);
    S.inventory.environment.longPaths = r.ok ? (on ? 'enabled' : 'disabled') : 'unknown';
    if (r.ok && !on) S.add({ severity: 'info', area, title: 'Windows long path support is off', detail: `Worktrees live under ${join(P.worktreesDir, '<id>', '<project>')}. Projects with deeply nested files (for example node_modules) can exceed Windows' 260-character limit there, which makes Git and tools fail with "Filename too long".`, steps: ['Optional: enable long paths (admin PowerShell): New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem" -Name LongPathsEnabled -Value 1 -PropertyType DWORD -Force', 'Then restart Windows.'] });
  }
}

async function checkInstallation({ P, S, opts }) {
  const area = 'Installation';
  const candidates = installCandidates(opts, P);
  const found = [];
  for (const c of candidates) {
    const res = resourcesOf(c.dir);
    const bundle = join(res, 'orchestrator', 'orchestrator.js');
    if (!isFile(join(res, 'app.asar')) && !isFile(bundle)) continue;
    let pkg = null; try { pkg = readAsarPackage(join(res, 'app.asar')); } catch {}
    const build = readJson(join(res, 'orchestrator', 'build-info.json'));
    found.push({ ...c, res, bundle, version: pkg?.version ?? null, commit: build.value?.commitSha ?? null });
  }
  S.inventory.installs = found;
  if (!found.length) {
    S.add({ severity: 'error', area, title: 'Freebuff installation not found', detail: `Looked in: ${candidates.map((c) => c.dir).join('; ') || '(nowhere)'}`,
      steps: ['If Freebuff is installed somewhere unusual, run the repair tool again with --install "<folder containing Freebuff.exe>".', 'Otherwise reinstall Freebuff from https://freebuff.com — your chats and projects are kept in your profile, not in the install folder.'] });
    return;
  }
  const main = found[0];
  S.install = main;
  S.inventory.environment.freebuffVersion = main.version;
  if (found.length > 1) {
    S.add({ severity: 'warn', area, title: `${found.length} Freebuff installations found`, detail: 'Several copies share one profile. Starting an older copy after a newer one can leave data the older one does not understand, and only one copy can run at a time.',
      evidence: found.map((f) => `${f.dir} — version ${f.version ?? '?'} (${f.how})`), steps: ['Keep only the newest copy: uninstall the others from Settings → Apps → Installed apps (your chats are kept).'] });
  }
  S.ok(area, `Freebuff ${main.version ?? '(unknown version)'} found`, `${main.dir} (${main.how})`);
  if (main.version && main.version !== BUILT_FOR) S.add({ severity: 'info', area, title: `This repair tool was built against Freebuff ${BUILT_FOR}; you have ${main.version}`, detail: 'Checks use the identity rules from your installed copy where possible. A few release-specific checks (file hashes) are skipped.' });

  const res = main.res;
  const exeName = IS_WIN ? 'Freebuff.exe' : IS_MAC ? join('MacOS', 'Freebuff') : 'freebuff';
  const required = [
    [IS_MAC ? join(main.dir, 'MacOS', 'Freebuff') : join(main.dir, exeName), 'app executable', !IS_WIN && !IS_MAC],
    [join(res, 'app.asar'), 'application code (app.asar)'],
    [join(res, 'orchestrator', 'orchestrator.js'), 'orchestrator (the background service that runs chats)'],
    [join(res, 'orchestrator', 'ui', 'index.html'), 'interface files'],
    [join(res, 'bun', IS_WIN ? 'bun.exe' : 'bun'), 'Bun runtime'],
    ...(IS_WIN ? [[join(res, 'bun', 'bun-baseline.exe'), 'Bun runtime for older CPUs', true], [join(res, 'git', 'cmd', 'git.exe'), 'bundled Git'], [join(res, 'orchestrator', 'windows-command.exe'), 'Windows command helper']] : []),
  ];
  const missing = required.filter(([p, , optional]) => !optional && !existsSync(p));
  if (missing.length) {
    S.add({ severity: 'error', area, title: 'Freebuff installation is incomplete', detail: 'Required files are missing. Antivirus software sometimes quarantines bun.exe or Git files.',
      evidence: missing.map(([p, what]) => `missing ${what}: ${p}`),
      steps: ['Check your antivirus quarantine/history for Freebuff files and restore them (mark them as allowed).', 'Reinstall Freebuff from https://freebuff.com (your chats and projects are kept).'] });
  } else S.ok(area, 'All required installation files are present');

  const manifest = RELEASE_MANIFESTS[main.version];
  if (manifest && manifest.platform === process.platform) {
    if (main.commit && main.commit !== manifest.commit) S.add({ severity: 'warn', area, title: 'Build commit differs from the official release', detail: `Expected ${manifest.commit}, found ${main.commit}.` });
    const bad = [];
    for (const [rel, want] of Object.entries(manifest.hashes ?? {})) {
      const p = join(main.dir, ...rel.split('/'));
      const s = statSafe(p);
      if (!s) { bad.push(`${rel}: missing`); continue; }
      if (s.size !== want.size) { bad.push(`${rel}: size ${s.size} (expected ${want.size})`); continue; }
      if (opts.deep || /orchestrator\.js$|build-info\.json$|app-update\.yml$|claude-elevation-hook\.js$/.test(rel)) {
        const h = sha256File(p); if (h !== want.sha256) bad.push(`${rel}: content differs (sha256 ${h.slice(0, 16)}…)`);
      }
    }
    const dirsBad = [];
    for (const [g, want] of Object.entries(manifest.dirs)) {
      const base = g === '.' ? main.dir : join(main.dir, ...g.split('/'));
      const list = [];
      const walk = (d) => { for (const e of listDir(d)) { const q = join(d, e.name); if (e.isDirectory()) { if (g === '.' || g === 'resources') continue; walk(q); } else if (e.isFile()) { const r = relative(main.dir, q).split(sep).join('/'); if (g === '.' && /^uninstall .*\.exe$/i.test(r)) continue; list.push([r.toLowerCase(), statSafe(q)?.size ?? 0]); } } };
      walk(base);
      list.sort((a, b) => (a[0] < b[0] ? -1 : 1));
      const digest = sha(list.map((x) => x.join('\t')).join('\n')).slice(0, 32);
      if (digest !== want.digest) dirsBad.push(`${g}/: ${list.length} files, ${fmtBytes(list.reduce((s, x) => s + x[1], 0))} (official: ${want.files} files, ${fmtBytes(want.bytes)})`);
    }
    if (bad.length || dirsBad.length) {
      S.add({ severity: 'error', area, title: 'Installation files differ from the official release', detail: 'Files are missing, truncated or modified. Typical causes: antivirus quarantine, an interrupted update, disk errors, or manual changes.',
        evidence: [...bad, ...dirsBad], steps: ['Check your antivirus quarantine for Freebuff files (bun.exe, git files) and restore/allow them.', 'Reinstall Freebuff from https://freebuff.com. Your profile (chats, projects, sign-in) is stored separately and is kept.'] });
    } else S.ok(area, `Installation matches the official ${main.version} release${opts.deep ? ' (all key files hashed)' : ' (sizes and file lists; use --deep to hash everything)'}`);
  }

  const bunExe = join(res, 'bun', IS_WIN ? 'bun.exe' : 'bun');
  if (isFile(bunExe)) {
    const r = sh(bunExe, ['--version'], { timeout: 20000 });
    S.inventory.bunProbe = r.ok ? r.stdout : `failed (${r.code ?? r.error}) ${r.stderr.slice(0, 200)}`;
    if (!r.ok) {
      const base = join(res, 'bun', 'bun-baseline.exe');
      const rb = isFile(base) ? sh(base, ['--version']) : null;
      S.add({ severity: rb?.ok ? 'warn' : 'error', area, title: 'The bundled Bun runtime does not start', detail: rb?.ok ? 'The standard runtime fails but the baseline (older-CPU) runtime works. Freebuff switches to it automatically after a failed start.' : 'Freebuff cannot run its background service without it.',
        evidence: [`${bunExe}: exit ${r.code ?? r.error} ${r.stderr.slice(0, 300)}`, ...(rb ? [`baseline: ${rb.ok ? rb.stdout : `exit ${rb.code}`}`] : [])],
        steps: ['Make sure antivirus is not blocking bun.exe (add the Freebuff install folder as an exclusion).', 'Reinstall Freebuff.'] });
    } else S.ok(area, `Bundled Bun ${r.stdout} starts`);
  }
  const mem = readJson(join(P.userData, 'bun-runtime.json'));
  if (mem.status === 'ok') { S.inventory.bunRuntimeMemory = mem.value; if (JSON.stringify(mem.value).includes('baseline')) S.add({ severity: 'info', area, title: 'Freebuff is pinned to the baseline (older-CPU) Bun runtime', detail: 'A previous start of the standard runtime crashed, so the slower baseline runtime is used. This is automatic and safe.', evidence: [JSON.stringify(mem.value)] }); }
  const git = makeGit(res);
  const gv = git.run(P.home, ['--version']);
  S.inventory.git = { exe: git.exe, bundled: git.bundled, version: gv.ok ? gv.stdout : `failed: ${gv.stderr || gv.error}` };
  if (!gv.ok) S.add({ severity: IS_WIN ? 'error' : 'warn', area, title: 'Git does not run', detail: `${git.exe} failed to start. Freebuff needs Git for projects, worktrees and change tracking.`, evidence: [gv.stderr || gv.error || `exit ${gv.code}`], steps: IS_WIN ? ['Allow the Freebuff folder in your antivirus and reinstall Freebuff.'] : ['Install Git (macOS: xcode-select --install; Linux: your package manager).'] });
  else S.ok(area, `Git works (${gv.stdout}${git.bundled ? ', bundled' : ', system'})`);

  const upd = statSafe(P.updaterCache);
  if (upd) {
    const pending = join(P.updaterCache, 'pending');
    const files = listDir(pending).filter((e) => e.isFile()).map((e) => e.name);
    S.inventory.updaterCache = { dir: P.updaterCache, pending: files };
    if (files.some((f) => /\.(exe|zip|dmg|AppImage)$/i.test(f))) S.add({ severity: 'info', area, title: 'An update has been downloaded and is waiting', detail: 'It installs when Freebuff restarts.', evidence: files });
  }
  const updPrefs = readJson(join(P.userData, 'update-preferences.json'));
  if (updPrefs.status === 'ok') S.inventory.updatePreferences = updPrefs.value;
}

function checkProcesses({ P, S }) {
  const area = 'Freebuff process';
  const procs = runningProcesses();
  const lock = profileLockState(P.statePath);
  S.procs = procs; S.lock = lock;
  S.appRunning = appBlocks(lock, procs, S.install);
  S.inventory.processes = procs.map((p) => ({ pid: p.pid, kind: p.kind, exe: p.exe }));
  S.inventory.profileLock = lock;
  const ours = procs.filter((p) => !S.install || !isAbsolute(p.exe ?? '') || within(p.exe, S.install.dir));
  const apps = ours.filter((p) => p.kind === 'app'), orch = ours.filter((p) => p.kind === 'orchestrator');
  const others = procs.filter((p) => (p.kind === 'app' || p.kind === 'orchestrator') && !ours.includes(p));
  if (others.length && lock.state !== 'held') S.add({ severity: 'info', area, title: 'Another Freebuff copy is running', detail: 'It runs from a different folder and does not hold this profile\'s lock, so it is not using the profile being examined.', evidence: [...new Set(others.map((p) => p.exe))] });
  if (lock.state === 'held') S.add({ severity: 'info', area, title: 'Freebuff is running', detail: 'The profile is in use by a running Freebuff. The scan is read-only and safe while it runs, but repairs need Freebuff fully closed.', evidence: Object.entries(Object.groupBy(procs.filter((p) => p.kind !== 'git'), (p) => `${p.kind}: ${p.exe}`)).map(([k, v]) => `${k} (pid ${v.map((p) => p.pid).join(', ')})`) });
  else if (orch.length && !apps.length) S.add({ severity: 'warn', area, title: 'A Freebuff background service is running without the app window', detail: 'A leftover orchestrator process can keep files locked and make the next start fail with "Another Freebuff orchestrator is already using this Desktop state profile".', evidence: orch.map((p) => `pid ${p.pid}: ${p.cmd || p.exe}`), steps: [IS_WIN ? 'Open Task Manager → Details, end the listed bun.exe processes (only those whose command line mentions orchestrator.js), then start Freebuff.' : `Run: kill ${orch.map((p) => p.pid).join(' ')}  — then start Freebuff.`] });
  else if (!S.appRunning) S.ok(area, 'Freebuff is not running (repairs are possible)');
  if (lock.state === 'error') S.add({ severity: 'warn', area, title: 'The profile lock file could not be checked', detail: lock.error, evidence: [lock.path], steps: ['If Freebuff reports "could not lock the state profile", make sure the profile folder is writable and not inside a synced folder.'] });
  const running = [...apps, ...orch].map((p) => p.exe).filter(Boolean);
  if (S.install && running.length) {
    const other = running.filter((e) => !within(e, S.install.dir) && isAbsolute(e));
    if (other.length) S.add({ severity: 'warn', area, title: 'The running Freebuff is a different copy than the one examined', detail: 'Checks used the installation found on disk, but the app that is running comes from another folder.', evidence: [...new Set(other)], steps: ['Quit Freebuff, remove the extra copy, and run the repair tool again (or pass --install).'] });
  }
}

async function checkIdentityFunctions({ S, P }) {
  const area = 'Repair tool';
  S.identity = embeddedIdentity; S.identitySource = `embedded copy (Freebuff ${BUILT_FOR})`;
  if (!S.install || !isFile(S.install.bundle)) return;
  try {
    const installed = loadBundleIdentity(S.install.bundle);
    const probeDir = P.home;
    const a = await installed.deviceFolderIdentity(probeDir), b = await embeddedIdentity.deviceFolderIdentity(probeDir);
    const args = [API_HOST, 'probe-account', '00000000-0000-4000-a000-000000000000'];
    const same = JSON.stringify(a) === JSON.stringify(b) && installed.deviceFolderBinding(...args, a) === embeddedIdentity.deviceFolderBinding(...args, b);
    S.identity = installed; S.identitySource = `installed Freebuff ${S.install.version ?? ''} (${same ? 'matches' : 'DIFFERS FROM'} the embedded ${BUILT_FOR} copy)`.replace('  ', ' ');
    if (!same) S.add({ severity: 'info', area, title: 'Your Freebuff computes folder identities differently from the release this repair tool knows', detail: 'The repair tool uses the rules from your installed copy, which is the accurate choice.' });
  } catch (e) {
    const absent = /not found in this build/.test(e.message);
    S.add({ severity: 'info', area, title: absent ? 'Your Freebuff version does not fingerprint project folders' : 'Using the repair tool\'s built-in folder identity rules', detail: absent ? `Folder fingerprints (and the error "The local checkout changed") were added in a later version than ${S.install.version ?? "yours"}. Folder-approval checks use the ${BUILT_FOR} rules.` : `Could not load them from the installed app (${e.message}). Results are exact for Freebuff ${BUILT_FOR}.` });
  }
}

function checkProfile({ P, S }) {
  const area = 'Profile';
  S.inventory.profile = { statePath: P.statePath, userData: P.userData, logs: P.logsDir };
  if (!isDir(P.profileDir)) {
    S.add({ severity: 'warn', area, title: 'No Freebuff profile found', detail: `${P.profileDir} does not exist. Either Freebuff has never been started by this Windows user, or the profile was deleted.`, steps: ['Start Freebuff and sign in once. If you expected existing chats, check that you are logged into the same Windows account you used before.'] });
    S.state = {}; return;
  }
  const r = readJson(P.statePath);
  S.stateRaw = r;
  if (r.status === 'missing') { S.add({ severity: 'warn', area, title: 'state.json is missing', detail: 'Freebuff will create a fresh one. Previously added projects, folder approvals and the computer ID (installId) are gone, so chats that ran on this computer may now be treated as running on "another computer".', steps: ['If you have a backup of the .config\\freebuff-desktop folder, restore state.json from it while Freebuff is closed.'] }); S.state = {}; }
  else if (r.status === 'unreadable') { S.add({ severity: 'error', area, title: 'state.json cannot be read', detail: `Error: ${r.error}. Freebuff will refuse to save settings.`, steps: ['Make sure the file is not locked by antivirus or a sync tool, and that your user has permission to it.'] }); S.state = {}; }
  else if (r.status === 'corrupt' || typeof r.value !== 'object' || Array.isArray(r.value) || !r.value) {
    S.add({ severity: 'error', area, title: 'state.json is corrupted', detail: `It is not valid JSON (${r.error ?? 'not an object'}). The next time Freebuff saves anything it moves this file aside and starts a fresh profile — losing project list, folder approvals and this computer's ID.`, steps: ['Close Freebuff now, before it overwrites the file.', 'Run the repair tool with --fix; it will try to salvage the file.', 'Otherwise restore state.json from a backup.'] });
    S.state = {};
  } else { S.state = r.value; S.ok(area, `state.json is valid (${fmtBytes(r.bytes)})`); }
  const st = S.state;

  const files = listDir(P.profileDir).filter((e) => e.isFile()).map((e) => e.name);
  S.inventory.profileFiles = files.map((n) => { const s = statSafe(join(P.profileDir, n)); return { name: n, size: s?.size, modified: s?.mtimeMs }; });
  const base = basename(P.statePath);
  const corrupt = files.filter((n) => n.startsWith(`${base}.corrupt-`));
  if (corrupt.length) {
    const details = corrupt.map((n) => {
      const text = readText(join(P.profileDir, n)) ?? '';
      const id = text.match(/"installId"\s*:\s*"([0-9a-f-]{36})"/i)?.[1];
      return { name: n, size: text.length, installId: id, nul: /\u0000/.test(text) };
    });
    S.corruptStates = details;
    const changedId = details.find((d) => d.installId && st.installId && d.installId !== st.installId);
    S.add({ severity: changedId ? 'error' : 'warn', area, key: 'profile:corrupt-aside', title: 'Freebuff reset your profile after finding it corrupted', detail: `Freebuff found state.json unreadable at some point and moved it aside (${corrupt.join(', ')}). ${changedId ? `The computer ID changed from ${short(changedId.installId)}… to ${short(st.installId)}…, so chats that ran on this computer before the reset are now treated as running on a different computer ("The computer this chat runs on is asleep or unreachable" or "Move this chat to Cloud on its original computer first"), and projects/folder approvals from before were lost.` : 'Projects and folder approvals saved before the reset were lost.'}`,
      evidence: details.map((d) => `${d.name}: ${fmtBytes(d.size)}${d.nul ? ', contains NUL bytes (typical of a crash or power loss while writing)' : ''}${d.installId ? `, installId ${d.installId}` : ', no readable installId'}`),
      steps: ['Re-add your project folders with "Open local folder".', changedId ? 'Run the repair tool with --fix to restore the previous computer ID (this makes old chats local again, but chats started after the reset would then look like they belong to another computer — the repair tool explains before changing anything).' : 'Start new chats for work that was in progress.'],
      fix: changedId ? salvageInstallIdFix(P, st, changedId) : undefined });
  }
  if (files.includes(`${base}.tmp`)) S.add({ severity: 'info', area, title: 'Leftover state.json.tmp', detail: 'A save was interrupted (crash or power loss). Freebuff deletes it on the next save; it is harmless.' });
  for (const n of files.filter((f) => f.startsWith(base) && f.endsWith('.json') && f !== base && !f.includes('.corrupt-'))) {
    const j = readJson(join(P.profileDir, n));
    if (j.status === 'corrupt' && j.bytes > 0) S.add({ severity: 'warn', area, title: `${n} is not valid JSON`, detail: 'Freebuff treats an unreadable side file as empty; the information in it is ignored.', evidence: [`${fmtBytes(j.bytes)}: ${j.error}`], steps: ['Usually harmless. Quit Freebuff and move the file to another folder if Freebuff misbehaves.'] });
  }
  const transition = readJson(`${P.statePath}.build-transition.json`);
  if (transition.status === 'ok') {
    S.inventory.buildTransition = transition.value;
    const { currentVersion: cur, previousVersion: prev } = transition.value;
    const cmp = (a, b) => { const x = String(a).split('.').map(Number), y = String(b).split('.').map(Number); for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0); return 0; };
    if (prev && cur && cmp(cur, prev) < 0) S.add({ severity: 'warn', area, title: `Freebuff was downgraded (${prev} → ${cur})`, detail: 'An older version may not understand data written by the newer one. Chats created or migrated by the newer version can misbehave.', steps: ['Update to the latest Freebuff from https://freebuff.com.'] });
  }

  if (r.status === 'ok') {
    if (!st.installId) S.add({ severity: 'info', area, title: 'No computer ID (installId) yet', detail: 'Freebuff creates it the first time it needs it.' });
    else if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(st.installId)) S.add({ severity: 'error', area, title: 'The computer ID (installId) is malformed', detail: `"${truncate(st.installId, 50)}" is not a valid ID. Freebuff will generate a new one, which detaches existing chats from this computer.`, steps: ['Restore state.json from a backup if possible.'] });
    S.inventory.installId = st.installId;
    const known = new Set(['installId', 'analyticsId', 'machineId', 'authSessions', 'authToken', 'authHost', 'authUser', 'projects', 'projectNames', 'recentProjects', 'removedProjects', 'workspace', 'uiPrefs', 'composerDrafts', 'fileEdits', 'terminalContexts', 'diffComments', 'agentHarness', 'executionModeByProject', 'deviceReconnectGrants']);
    S.inventory.stateKeys = Object.keys(st).map((k) => (known.has(k) ? k : `${k} (unknown to ${BUILT_FOR})`));
  }
  const sync = syncedFolderKind(P.profileDir);
  if (sync) S.add({ severity: 'warn', area, title: `Your Freebuff profile is inside ${sync}`, detail: 'Sync tools can lock or replace files while Freebuff writes them, corrupting state.json and chat databases.', evidence: [P.profileDir], steps: [`Exclude ${P.profileDir} from ${sync}, or move your home folder's .config out of the synced location.`] });
}

function syncedFolderKind(p) {
  const s = String(p);
  for (const v of ['OneDrive', 'OneDriveConsumer', 'OneDriveCommercial']) { const root = process.env[v]; if (root && within(s, root)) return 'OneDrive'; }
  if (/[\\/]OneDrive( - [^\\/]+)?[\\/]/i.test(s)) return 'OneDrive';
  if (/[\\/]Dropbox[\\/]/i.test(s)) return 'Dropbox';
  if (/[\\/](Google Drive|GoogleDrive|My Drive)[\\/]/i.test(s)) return 'Google Drive';
  if (/[\\/](iCloud Drive|iCloudDrive|Mobile Documents)[\\/]/i.test(s)) return 'iCloud Drive';
  if (/[\\/]Box( Sync)?[\\/]/i.test(s)) return 'Box';
  if (/[\\/]pCloud ?Drive[\\/]/i.test(s)) return 'pCloud';
  return null;
}

function checkAuth({ P, S }) {
  const area = 'Sign-in';
  const st = S.state ?? {};
  const sessions = st.authSessions && typeof st.authSessions === 'object' ? st.authSessions : {};
  const plain = sessions[API_HOST] ?? (st.authToken ? { token: st.authToken, user: st.authUser } : null);
  const secrets = readJson(`${P.statePath}.auth-secrets.json`);
  const encKey = `auth/${sha(API_HOST)}`;
  const encrypted = secrets.status === 'ok' && typeof secrets.value?.[encKey] === 'string';
  const deviceKeyPlain = isFile(`${P.statePath}.device-key.json`);
  const deviceKeyEnc = secrets.status === 'ok' && Object.keys(secrets.value ?? {}).some((k) => k === `auth/${sha('freebuff-device-key:v1')}`);
  const accounts = new Map();
  const bump = (id, why) => { if (id) accounts.set(id, [...(accounts.get(id) ?? []), why]); };
  if (plain?.user?.id) bump(plain.user.id, 'signed-in user');
  for (const p of Object.values(st.projects ?? {})) bump(p?.accountId, 'project');
  for (const g of st.deviceReconnectGrants ?? []) bump(g?.accountId, 'folder approval');
  S.accounts = accounts;
  S.accountId = plain?.user?.id ?? [...accounts.entries()].sort((a, b) => b[1].length - a[1].length)[0]?.[0] ?? null;
  S.accountSource = plain?.user?.id ? 'sign-in' : S.accountId ? 'inferred from saved projects/approvals' : 'unknown';
  const storage = plain?.token ? 'stored unencrypted in state.json (this computer has no secure storage)' : encrypted ? 'encrypted with the operating system\'s secure storage' : 'none';
  S.inventory.auth = { signedIn: !!(plain?.token || encrypted), storage, account: S.accountId ? `${short(S.accountId)}… (${S.accountSource})` : 'unknown', email: plain?.user?.email ?? null, deviceKey: deviceKeyEnc ? 'encrypted' : deviceKeyPlain ? 'local owner-only file' : 'none yet' };
  if (!plain?.token && !encrypted) S.add({ severity: 'warn', area, title: 'Not signed in', detail: 'No saved sign-in for Freebuff was found in this profile.', steps: ['Open Freebuff and sign in. Use the same account as before so your Cloud chats appear.'] });
  else S.ok(area, `Signed in (${storage})`);
  if (secrets.status === 'corrupt') S.add({ severity: 'error', area, title: 'The encrypted sign-in file is corrupted', detail: 'state.json.auth-secrets.json is not valid JSON, so Freebuff cannot read your sign-in or device key.', steps: ['Quit Freebuff, move state.json.auth-secrets.json out of the profile folder, start Freebuff and sign in again.'] });
  if (accounts.size > 1) S.add({ severity: 'warn', area, title: `This profile holds data from ${accounts.size} different accounts`, detail: 'Chats and folder approvals belong to the account that created them. While signed in as a different account, they show errors such as "This chat belongs to another account or environment" or "Account changed. Sign in again to open this project."',
    evidence: [...accounts.entries()].map(([id, why]) => `${short(id)}…: ${[...new Set(why)].map((w) => `${why.filter((x) => x === w).length} ${w}(s)`).join(', ')}${id === S.accountId ? ' ← current' : ''}`), steps: ['Sign in with the account that owns the chat you are trying to open.'] });
  const lastLog = tailFile(join(P.logsDir, 'orchestrator-stderr.log'), 256 * 1024) ?? '';
  if (/encrypted sign-in could not be decrypted on this machine/.test(lastLog)) S.add({ severity: 'warn', area, title: 'Your saved sign-in could not be decrypted', detail: 'Windows protects the saved sign-in with your Windows password. After a password reset, a profile migration or copying the profile to another PC it cannot be decrypted, and Freebuff signs you out.', steps: ['Sign in again in Freebuff. Nothing else is lost.'] });
}

function checkProjects({ P, S }) {
  const area = 'Projects';
  const st = S.state ?? {};
  const projects = st.projects && typeof st.projects === 'object' ? st.projects : {};
  const removed = st.removedProjects ?? {};
  const list = [];
  for (const [path, p] of Object.entries(projects)) {
    const s = statSafe(path);
    const managed = within(path, P.profileDir);
    list.push({ path, name: p?.name ?? basename(path), id: p?.id, cloudProjectId: p?.cloudProjectId, location: p?.location, accountId: p?.accountId, exists: !!s?.isDirectory(), managed, removed: path in removed, sync: managed ? null : syncedFolderKind(path) });
  }
  S.projectsList = list;
  S.inventory.projects = list;
  const missing = list.filter((p) => !p.exists && !p.removed && !p.managed && p.location === 'local');
  if (missing.length) S.add({ severity: 'error', area, key: 'projects:missing', title: `${missing.length} project folder(s) no longer exist`, detail: 'Freebuff remembers these folders, but nothing is at that path now. Chats that ran in them cannot continue locally; "Open local folder" on a different folder does not reconnect old chats.',
    evidence: missing.map((p) => `${p.name}: ${p.path}`), steps: ['If you moved or renamed the folder, move it back to exactly this path (a fresh clone or copy is not the same folder).', 'If it was deleted on purpose, remove the project from Freebuff\'s sidebar and start new chats in the new folder.'] });
  else if (list.some((p) => !p.managed)) S.ok(area, `All ${list.filter((p) => !p.managed).length} local project folder(s) exist`);
  else if (list.length) S.ok(area, `${list.length} app-managed project(s); no local project folders added`);
  for (const p of list.filter((x) => x.sync && x.exists)) S.add({ severity: 'warn', area, title: `Project "${p.name}" is inside ${p.sync}`, detail: `Sync tools may delete and recreate folders while syncing. Freebuff identifies a folder by its file-system ID, so a recreated folder at the same path counts as a different folder, which breaks existing chats with "The local checkout changed; reconnect the original folder". They also fight with Git over .git files.`, evidence: [p.path], steps: [`Keep code projects outside ${p.sync} (for example C:\\dev\\${basename(p.path)}), or pause syncing for this folder.`] });
  for (const p of list.filter((x) => x.exists && !x.managed)) {
    const canon = canonical(p.path);
    if (canon !== p.path && !samePathish(canon, p.path)) S.add({ severity: 'info', area, title: `Project "${p.name}" is reached through a link`, detail: 'The saved path goes through a junction, symbolic link or mapped/substituted drive. Freebuff uses the real path for folder identity, so this works — but if the link is changed to point somewhere else, chats will report "The local checkout changed".', evidence: [`saved: ${p.path}`, `real:  ${canon}`] });
    if (IS_WIN && /^\\\\/.test(canon)) S.add({ severity: 'warn', area, title: `Project "${p.name}" is on a network share`, detail: 'Network shares often report unstable folder IDs and cannot host SQLite databases reliably. Chats may fail with "The local checkout changed" after reconnecting the share.', evidence: [canon], steps: ['Move the project to a local drive.'] });
  }
  const recents = Array.isArray(st.recentProjects) ? st.recentProjects : [];
  const deadRecents = recents.filter((p) => typeof p === 'string' && !isDir(p));
  if (deadRecents.length) S.add({ severity: 'info', area, title: `${deadRecents.length} recent project(s) point to missing folders`, evidence: deadRecents, steps: ['Harmless; they disappear from the recents list over time.'] });
  const tabs = st.workspace?.tabs ?? [];
  const deadTabs = tabs.filter((t) => t?.projectPath && !isDir(t.projectPath));
  if (deadTabs.length) S.add({ severity: 'info', area, title: `${deadTabs.length} open tab(s) belong to missing project folders`, evidence: [...new Set(deadTabs.map((t) => t.projectPath))], steps: ['Close those tabs in Freebuff.'] });
}

function openRO(path) { return openDb(path, { readonly: true }); }
function tableColumns(db, table) { try { return new Set(db.query(`PRAGMA table_info(${table})`).all().map((c) => c.name)); } catch { return new Set(); } }

function checkDatabases({ P, S, opts }) {
  const area = 'Chat databases';
  const root = join(P.profileDir, 'projects');
  const dirs = listDir(root).filter((e) => e.isDirectory()).map((e) => e.name);
  S.dbs = [];
  const byId = new Map(), byPath = new Map();
  for (const name of dirs) {
    const dir = join(root, name);
    const meta = readJson(join(dir, 'project.json'));
    const m = meta.status === 'ok' ? meta.value : null;
    const idFromName = name.match(/-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/)?.[1] ?? null;
    const metaValid = !!m && m.version === 1 && typeof m.projectId === 'string' && PROJECT_ID_RE.test(m.projectId) && typeof m.projectPath === 'string' && m.database === DB_FILENAME;
    const entry = { dir, name, idFromName, meta: m, metaStatus: meta.status, metaValid, projectId: metaValid ? m.projectId : idFromName, projectPath: m?.projectPath ?? null, dbPath: join(dir, DB_FILENAME) };
    S.dbs.push(entry);
    if (entry.projectId) byId.set(entry.projectId, [...(byId.get(entry.projectId) ?? []), entry]);
    if (entry.projectPath) { const k = normPath(entry.projectPath); byPath.set(k, [...(byPath.get(k) ?? []), entry]); }

    if (!metaValid) S.add({ severity: meta.status === 'missing' ? 'warn' : 'error', area, title: `Project database folder "${truncate(name, 40)}" has ${meta.status === 'missing' ? 'no' : 'an invalid'} project.json`, detail: 'Freebuff tries to rebuild it from the database. If it cannot tell which folder the database belongs to, it refuses to open it ("Freebuff could not verify which project owns the local database").', evidence: [join(dir, 'project.json') + (meta.error ? `: ${meta.error}` : '')], steps: ['Usually Freebuff repairs this itself when you open the project. If it reports it cannot verify the owner, contact support with this report.'] });
    else if (idFromName && idFromName !== m.projectId) S.add({ severity: 'error', area, title: `Database folder name and project.json disagree`, detail: 'Freebuff will refuse to use this database ("its project.json names a different project").', evidence: [`${name}: folder id ${idFromName}, project.json ${m.projectId}`], steps: ['Contact support with this report.'] });

    for (const e of listDir(dir)) {
      if (e.isDirectory() && e.name.startsWith('.migration-')) S.add({ severity: 'info', area, title: 'Leftover database migration folder', detail: 'An upgrade of an older database was interrupted. It is not used.', evidence: [join(dir, e.name)], fix: { id: `migration-leftover:${dir}/${e.name}`, title: `Move leftover ${e.name} out of the profile`, risk: 'none', apply: (fx) => fx.moveAside(join(dir, e.name)) } });
    }
    const st = statSafe(entry.dbPath), wal = statSafe(`${entry.dbPath}-wal`);
    entry.size = st?.size ?? 0; entry.walSize = wal?.size ?? 0;
    if (!st) { if (wal || existsSync(`${entry.dbPath}-journal`)) S.add({ severity: 'error', area, title: `Database file missing but its journal remains`, detail: 'Freebuff will refuse to open this project\'s history ("its database file is missing").', evidence: [entry.dbPath], steps: ['Look for desktop-v2.db in your backups or antivirus quarantine and restore it into this folder.'] }); continue; }
    let db;
    try {
      db = openRO(entry.dbPath);
      const check = db.query(opts.deep ? 'PRAGMA integrity_check' : 'PRAGMA quick_check').all().map((r) => Object.values(r)[0]);
      entry.integrity = check.length === 1 && check[0] === 'ok' ? 'ok' : check;
      const objects = new Set(db.query("SELECT name FROM sqlite_master WHERE type IN ('table','index','trigger')").all().map((r) => r.name));
      entry.missingObjects = SCHEMA_OBJECTS.filter((n) => !objects.has(n));
      entry.journalMode = db.query('PRAGMA journal_mode').get()?.journal_mode;
      if (objects.has('threads')) {
        const cols = tableColumns(db, 'threads');
        const want = ['id', 'project_id', 'project_path', 'title', 'status', 'execution_mode', 'execution_target', 'worktree_path', 'branch', 'source_branch', 'turn_state', 'cloud_account_id', 'cloud_api_host', 'cloud_handoff_pending', 'local_handoff_pending', 'local_history_only', 'next_execution_target', 'sidebar_archived_at', 'created_at', 'updated_at', 'last_prompt_at', 'workspace_epoch'];
        const sel = want.filter((c) => cols.has(c));
        entry.threads = db.query(`SELECT ${sel.join(', ')} FROM threads`).all();
        entry.messageCounts = Object.fromEntries(objects.has('messages') ? db.query('SELECT thread_id, count(*) AS n, max(ts) AS last FROM messages GROUP BY thread_id').all().map((r) => [r.thread_id, { n: r.n, last: r.last }]) : []);
        entry.projectRows = objects.has('projects') ? db.query('SELECT id, root_path FROM projects').all() : [];
        entry.queue = objects.has('queue_items') ? db.query("SELECT thread_id, state, count(*) AS n FROM queue_items GROUP BY thread_id, state").all() : [];
        entry.conflicts = objects.has('thread_landing_conflicts') ? db.query('SELECT thread_id, count(*) AS n FROM thread_landing_conflicts WHERE resolved_at IS NULL GROUP BY thread_id').all() : [];
      } else entry.threads = [];
    } catch (e) {
      entry.integrity = [e.message];
      entry.openError = e.message;
    } finally { try { db?.close(); } catch {} }

    if (entry.openError) {
      const locked = /locked|busy/i.test(entry.openError);
      S.add({ severity: locked ? 'warn' : 'error', area, key: `db-open:${dir}`, title: `${locked ? 'Database is locked' : 'Database cannot be opened'}: ${projectLabel(S, entry)}`, detail: locked ? 'Another program holds this database. Usually Freebuff itself (fine), otherwise a backup/sync/antivirus tool.' : `SQLite error: ${entry.openError}. Freebuff shows "Freebuff's local thread database for this project could not be read" for this project.`, evidence: [entry.dbPath, `${fmtBytes(entry.size)} + WAL ${fmtBytes(entry.walSize)}`],
        steps: locked ? ['Close Freebuff and any backup or sync tool, then run the repair tool again.'] : ['Run the repair tool with --fix: it will try to rebuild the database from the readable data (the original is kept as a backup).', 'If that fails, chat history for this project can only be recovered from a backup; Cloud chats re-download automatically.'],
        fix: locked ? undefined : dbRebuildFix(entry) });
    } else if (entry.integrity !== 'ok') {
      const onlyUnused = Array.isArray(entry.integrity) && entry.integrity.every((l) => /^Page \d+: never used$|^\*\*\* in database main \*\*\*$/.test(l));
      S.add({ severity: onlyUnused ? 'info' : 'error', area, key: `db-integrity:${dir}`, title: `${onlyUnused ? 'Database has unused pages' : 'Database is damaged'}: ${projectLabel(S, entry)}`, detail: onlyUnused ? 'Harmless; Freebuff compacts it automatically.' : 'SQLite reports corruption. Chats in this project can fail to load or save, and Freebuff may refuse to migrate it.',
        evidence: [entry.dbPath, ...(Array.isArray(entry.integrity) ? entry.integrity.slice(0, 8) : [])], steps: onlyUnused ? [] : ['Close Freebuff and run the repair tool with --fix to rebuild the database (the damaged one is backed up).', 'Check the disk for errors (Windows: chkdsk).'], fix: onlyUnused ? undefined : dbRebuildFix(entry) });
    }
    if (entry.missingObjects?.length) S.add({ severity: 'info', area, title: `Database for ${projectLabel(S, entry)} lacks ${entry.missingObjects.length} schema object(s)`, detail: 'Freebuff adds missing tables/indexes the next time it opens the project.', evidence: [entry.missingObjects.join(', ')] });
    if (entry.walSize > 256 << 20) S.add({ severity: 'info', area, title: `Large write-ahead log (${fmtBytes(entry.walSize)}) for ${projectLabel(S, entry)}`, detail: 'Usually means Freebuff was killed repeatedly before it could checkpoint. It shrinks after a clean quit.' });
    if (entry.projectPath && !isDir(entry.projectPath) && !within(entry.projectPath, P.profileDir)) entry.orphan = true;
  }
  for (const [id, entries] of byId) if (entries.length > 1) {
    const withHistory = entries.filter((e) => Object.keys(e.messageCounts ?? {}).length > 0);
    const empties = entries.filter((e) => !withHistory.includes(e));
    S.add({ severity: 'error', area, key: `dup-id:${id}`, title: `Multiple databases claim project identity ${short(id)}…`, detail: 'Freebuff refuses to open this project ("Freebuff found multiple local databases for project identity …; no database was opened").',
      evidence: entries.map((e) => `${e.dir} — ${Object.keys(e.messageCounts ?? {}).length} chat(s) with messages`),
      steps: withHistory.length === 1 ? ['Run the repair tool with --fix: it moves the empty duplicate(s) out of the way (backed up).'] : ['Contact support with this report; more than one copy holds history.'],
      fix: withHistory.length === 1 && empties.length ? { id: `dup-id:${id}`, title: `Move ${empties.length} empty duplicate database folder(s) for project ${short(id)}… out of the profile`, risk: 'low', apply: (fx) => { for (const e of empties) fx.moveAside(e.dir); } } : undefined });
  }
  S.dbsByPath = byPath;
  S.inventory.databases = S.dbs.map((e) => ({ folder: e.name, project: e.projectPath, id: e.projectId, size: e.size, wal: e.walSize, integrity: e.integrity === 'ok' ? 'ok' : 'PROBLEM', threads: e.threads?.length ?? 0 }));
  if (S.dbs.length && !S.findings.some((f) => f.area === area && f.severity === 'error')) S.ok(area, `${S.dbs.length} project database(s) open and pass ${opts.deep ? 'integrity_check' : 'quick_check'}`);

  for (const p of S.projectsList ?? []) {
    if (!p.exists || p.location !== 'local') continue;
    const markerPath = join(p.path, '.freebuff', 'project-id');
    const raw = readText(markerPath);
    const marker = raw?.trim().toLowerCase() ?? null;
    const forPath = byPath.get(normPath(p.path)) ?? [];
    const withHistory = forPath.filter((e) => Object.keys(e.messageCounts ?? {}).length > 0);
    p.marker = marker;
    if (raw !== null && !PROJECT_ID_RE.test(marker)) {
      S.add({ severity: 'error', area, title: `Invalid project identity marker in "${p.name}"`, detail: 'Freebuff refuses to open this project ("Freebuff found an invalid project identity marker").', evidence: [`${markerPath}: "${truncate(raw, 60)}"`],
        steps: ['Run the repair tool with --fix to point it back at the database that holds this folder\'s history, or delete the .freebuff\\project-id file so Freebuff re-links it.'], fix: withHistory.length === 1 ? markerFix(p, markerPath, raw, withHistory[0]) : undefined });
      continue;
    }
    const used = marker ? (byId.get(marker) ?? []) : [];
    p.dbInUse = used[0] ?? null;
    if (marker && used.length === 1 && !samePath(used[0].projectPath ?? '', p.path) && existsSync(used[0].projectPath ?? '')) {
      S.add({ severity: 'warn', area, title: `"${p.name}" shares its project identity with another folder`, detail: `This folder is a copy of ${used[0].projectPath} (its .freebuff\\project-id was copied too). When opened, Freebuff gives this folder a new identity and an empty chat history; the other folder keeps the history.`, evidence: [`${markerPath} = ${marker}`, `database belongs to ${used[0].projectPath}`], steps: ['Expected if you copied or re-cloned the project including its .freebuff folder. Open the original folder to see its chats.'] });
    } else if (marker && !used.length && withHistory.length === 1 && !byId.has(marker)) {
      S.add({ severity: 'error', area, key: `marker-orphan:${p.path}`, title: `Chat history for "${p.name}" is detached from the folder`, detail: `The folder's .freebuff\\project-id names an identity (${short(marker)}…) with no database, while a database holding this folder's ${Object.keys(withHistory[0].messageCounts).length} chat(s) exists under another identity. Freebuff will show this project with no chats.`,
        evidence: [`${markerPath} = ${marker}`, `history: ${withHistory[0].dir}`], steps: ['Run the repair tool with --fix to re-link the folder to its history (the old marker is backed up).'], fix: markerFix(p, markerPath, raw, withHistory[0]) });
    } else if (!marker && withHistory.length === 1) {
      S.add({ severity: 'info', area, title: `"${p.name}" has no .freebuff\\project-id marker`, detail: 'Freebuff re-links it to its existing history automatically next time the project opens.' });
    }
    const legacy = join(p.path, '.freebuff', DB_FILENAME);
    if (isFile(legacy)) S.add({ severity: 'info', area, title: `"${p.name}" still has an old in-project database`, detail: 'Older Freebuff versions stored history inside the project. Current versions copy it into the profile; the old file is no longer used once migrated.', evidence: [legacy] });
  }
}
function projectLabel(S, entry) {
  const p = (S.projectsList ?? []).find((x) => entry.projectPath && samePathish(resolve(x.path), resolve(entry.projectPath)));
  return p ? `"${p.name}"` : entry.projectPath ? `"${basename(entry.projectPath)}"` : entry.name;
}

async function checkGrants({ S }) {
  const area = 'Folder approvals';
  const st = S.state ?? {};
  const grants = Array.isArray(st.deviceReconnectGrants) ? st.deviceReconnectGrants : [];
  S.grants = [];
  const usesCloud = (S.dbs ?? []).some((d) => d.threads?.some((t) => t.execution_target === 'cloud')) || Object.values(st.projects ?? {}).some((p) => p?.deviceCloud);
  if (!grants.length && !usesCloud) return;
  if (!grants.length) { S.add({ severity: 'info', area, title: 'No saved folder approvals', detail: 'Approvals are saved when you choose "Open local folder" for a project that runs chats from the Cloud/web on this computer. Without one, such projects show "This folder is disconnected. Choose Open local folder to reconnect it."' }); return; }
  const id = S.identity ?? embeddedIdentity;
  for (const g of grants) {
    const r = { grant: g, project: (S.projectsList ?? []).find((p) => p.cloudProjectId === g.projectId || p.id === g.projectId)?.name ?? g.projectId };
    S.grants.push(r);
    const problems = [];
    if (g.version !== 1 || !UUID_RE.test(g.bindingId ?? '') || !UUID_RE.test(g.sessionId ?? '')) problems.push('approval record is malformed (Freebuff ignores it)');
    if (g.installId !== st.installId) problems.push(`made with a different computer ID (${short(g.installId)}… vs current ${short(st.installId)}…) — Freebuff ignores it`);
    if (S.accountId && g.accountId !== S.accountId) problems.push(`belongs to another account (${short(g.accountId)}…) — Freebuff ignores it while you are signed in as ${short(S.accountId)}…`);
    if (g.apiHost !== API_HOST) problems.push(`made for another server (${g.apiHost})`);
    try {
      const folder = await id.deviceFolderIdentity(g.path);
      const bindingId = id.deviceFolderBinding(g.apiHost, g.accountId, g.installId, folder);
      const sessionId = sessionIdFor(id, g.accountId, g.installId, bindingId);
      Object.assign(r, { now: folder, bindingId, sessionId });
      const why = [];
      if (folder.path !== g.path) why.push(`its real path is now ${folder.path} (approved as ${g.path})`);
      if (String(folder.dev) !== String(g.dev)) why.push(`it is on a different volume (volume ID ${g.dev} → ${folder.dev}): the drive was reformatted/replaced, or a network/removable drive changed`);
      if (String(folder.ino) !== String(g.ino)) why.push(`it is a different folder with the same name (folder ID ${g.ino} → ${folder.ino}): the folder was deleted and recreated — e.g. re-cloned, restored from backup, re-extracted, or recreated by a sync tool`);
      if (!why.length && (bindingId !== g.bindingId || sessionId !== g.sessionId)) why.push('the computed binding differs although the folder looks identical (unexpected — please send this report to support)');
      r.matches = !why.length;
      if (why.length) problems.push(...why.map((w) => `the folder changed since approval: ${w}`));
    } catch (e) {
      r.error = e.code ?? e.message;
      problems.push(e.code === 'ENOENT' ? 'the approved folder no longer exists at that path' : `cannot read the approved folder (${e.code ?? e.message})`);
    }
    r.problems = problems;
    if (problems.length) {
      const identityChanged = problems.some((p) => p.startsWith('the folder changed') || p.includes('no longer exists'));
      S.add({ severity: identityChanged ? 'error' : 'warn', area, key: `grant:${g.id}`, title: `Approval for "${r.project}" no longer matches its folder`, detail: identityChanged ? 'Chats that were started in this folder are bound to the folder as it was then. Opening them gives "The local checkout changed; reconnect the original folder". Re-approving the current folder fixes new chats only.' : 'Freebuff does not use this approval.',
        evidence: [`path: ${g.path}`, ...problems, `approved ${iso(g.approvedAt)}`],
        steps: identityChanged ? ['If you still have the ORIGINAL folder (moved, renamed, or on another drive), put it back at the approved path and choose "Open local folder" for it.', 'If the original folder is gone, a copy or fresh clone cannot stand in for it: choose "Open local folder" on the current folder and start a new chat there. The old chat\'s history stays readable.'] : ['Sign in with the matching account, or choose "Open local folder" again to create a fresh approval.'] });
    }
  }
  if (S.grants.length && S.grants.every((r) => !r.problems.length)) S.ok(area, `${S.grants.length} folder approval(s) still match their folders`);
}

function checkWorktrees({ P, S, opts }) {
  const area = 'Worktrees';
  S.worktrees = [];
  const owner = P.isRealProfile ? 'installed' : `profile-${sha(resolve(P.statePath)).slice(0, 8)}`;
  for (const shortDir of listDir(P.worktreesDir).filter((e) => e.isDirectory())) {
    const dir = join(P.worktreesDir, shortDir.name);
    for (const e of listDir(dir)) {
      if (!e.isDirectory()) continue;
      const path = join(dir, e.name);
      const claimRaw = readJson(`${path}.thread.json`);
      const claim = claimRaw.status === 'ok' ? claimRaw.value : null;
      const gitFile = readText(join(path, '.git'));
      const gitdir = gitFile?.match(/^gitdir:\s*(.+)\s*$/m)?.[1]?.trim() ?? null;
      const wt = { path, shortId: shortDir.name, claim, claimStatus: claimRaw.status, gitdir, gitdirExists: gitdir ? existsSync(isAbsolute(gitdir) ? gitdir : join(path, gitdir)) : false, bootstrapped: existsSync(`${path}.bootstrapped`), ours: claim?.owner === owner };
      if (opts.deep) wt.size = dirStats(path);
      S.worktrees.push(wt);
    }
  }
  for (const p of S.projectsList ?? []) {
    const legacy = join(p.path, '.freebuff', P.isRealProfile ? 'worktrees' : `worktrees-${sha(resolve(P.statePath)).slice(0, 8)}`);
    for (const e of listDir(legacy).filter((x) => x.isDirectory())) {
      const path = join(legacy, e.name), gitFile = readText(join(path, '.git'));
      const gitdir = gitFile?.match(/^gitdir:\s*(.+)\s*$/m)?.[1]?.trim() ?? null;
      S.worktrees.push({ path, legacy: true, threadId: e.name, projectRoot: p.path, gitdir, gitdirExists: gitdir ? existsSync(isAbsolute(gitdir) ? gitdir : join(path, gitdir)) : false, ours: true });
    }
  }
  S.inventory.worktrees = S.worktrees.map((w) => ({ path: w.path, thread: w.claim?.threadId ?? w.threadId ?? null, project: w.claim?.projectRoot ?? w.projectRoot ?? null, owner: w.claim?.owner ?? (w.legacy ? 'legacy' : null), git: w.gitdir ? (w.gitdirExists ? 'ok' : 'BROKEN') : 'not a worktree', size: w.size ? fmtBytes(w.size.bytes) : undefined }));
  const broken = S.worktrees.filter((w) => !w.gitdir || !w.gitdirExists);
  if (broken.length) S.add({ severity: 'warn', area, title: `${broken.length} worktree folder(s) are not usable Git worktrees`, detail: 'Their .git link is missing or points to a Git folder that no longer exists (for example after the main project was re-cloned or `git worktree prune` ran). Chats using them cannot run.',
    evidence: broken.map((w) => `${w.path}: ${w.gitdir ? `.git points to missing ${w.gitdir}` : 'no .git file'}`), steps: ['If the main project folder was replaced, the worktree cannot be repaired automatically; copy any work you need out of it and start a new worktree chat.', 'Advanced: `git worktree repair <worktree path>` run from the original project can relink it if the project\'s .git folder still exists.'] });
  const badClaims = S.worktrees.filter((w) => !w.legacy && w.claimStatus !== 'ok');
  if (badClaims.length) S.add({ severity: 'info', area, title: `${badClaims.length} worktree(s) have no readable owner record`, detail: 'The <worktree>.thread.json file that records which chat owns the worktree is missing or unreadable. Freebuff may refuse to reuse the folder ("belongs to another thread").', evidence: badClaims.map((w) => w.path) });
}

function worktreePathFor(P, root, threadId) {
  const legacy = join(root, '.freebuff', P.isRealProfile ? 'worktrees' : `worktrees-${sha(resolve(P.statePath)).slice(0, 8)}`, threadId);
  if (existsSync(legacy)) return legacy;
  const shortId = threadId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toLowerCase() || 'thread';
  const name = basename(root).replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'project';
  return join(P.worktreesDir, shortId, name);
}
function checkThreads({ P, S, opts }) {
  const area = 'Chats';
  const git = makeGit(S.install?.res);
  const threads = [];
  for (const db of S.dbs ?? []) for (const t of db.threads ?? []) threads.push({ ...t, db, messages: db.messageCounts?.[t.id]?.n ?? 0 });
  S.threads = threads;
  const label = (t) => `"${opts.hideTitles ? `chat ${short(t.id)}` : truncate(t.title, 60)}" (${short(t.id)}…, project ${basename(t.project_path ?? t.db.projectPath ?? '?')})`;
  const claimsByThread = new Map(S.worktrees?.filter((w) => w.claim?.threadId).map((w) => [w.claim.threadId, w]) ?? []);
  const referenced = new Set();
  let checked = 0;
  for (const t of threads) {
    checked++;
    const root = t.db.projectPath ?? t.project_path;
    if (t.worktree_path) referenced.add(normPath(t.worktree_path));
    const mode = t.execution_mode ?? 'local';
    const target = t.execution_target ?? 'local';
    if (mode === 'worktree' && !t.worktree_path) S.add({ severity: 'error', area, title: `Chat is in worktree mode but has no worktree: ${label(t)}`, detail: 'Freebuff will run it in the main project folder instead of its own checkout. For a chat started from the web/Cloud this gives "The local checkout changed; reconnect the original folder".', steps: ['Start a new chat; this one cannot find its checkout.'] });
    if (t.worktree_path) {
      const s = statSafe(t.worktree_path);
      if (!s?.isDirectory()) {
        S.add({ severity: 'error', area, key: `wt-missing:${t.id}`, title: `Chat's worktree folder is gone: ${label(t)}`, detail: 'The chat ran in its own checkout, which no longer exists. The chat cannot continue locally; chats started from the web/Cloud report "The local checkout changed; reconnect the original folder".', evidence: [t.worktree_path, `branch: ${t.branch ?? '?'}`],
          steps: [`If you moved this folder, put it back at exactly ${t.worktree_path}.`, `Your committed work may still exist on branch "${t.branch ?? '(unknown)'}" in the main project — check with: git -C "${root}" log --oneline -5 ${t.branch ?? ''}`, 'Otherwise start a new chat; the old history stays readable.'] });
      } else {
        const gf = readText(join(t.worktree_path, '.git'));
        if (gf === null && !isDir(join(t.worktree_path, '.git'))) S.add({ severity: 'error', area, title: `Chat's worktree is no longer a Git checkout: ${label(t)}`, detail: 'The folder exists but its .git link is gone, so Freebuff cannot track changes there.', evidence: [t.worktree_path], steps: ['Start a new worktree chat; copy any uncommitted files out of this folder first.'] });
        const claim = claimsByThread.get(t.id) ?? S.worktrees?.find((w) => samePath(w.path, t.worktree_path));
        if (claim?.claim && claim.claim.threadId !== t.id) S.add({ severity: 'warn', area, title: `Worktree is registered to a different chat: ${label(t)}`, detail: 'Two chats point at the same checkout. Freebuff refuses to recreate it ("belongs to another thread").', evidence: [t.worktree_path, `owner record says chat ${claim.claim.threadId}`] });
      }
    }
    if (!t.worktree_path && target === 'cloud' && root && isDir(root)) {
      const candidate = worktreePathFor(P, root, t.id);
      if (isDir(candidate)) {
        const claim = readJson(`${candidate}.thread.json`);
        const claimOk = claim.status === 'missing' || (claim.status === 'ok' && claim.value.threadId === t.id && samePath(claim.value.projectRoot, root));
        const head = git.run(candidate, ['symbolic-ref', '--short', '-q', 'HEAD']);
        const common = git.run(candidate, ['rev-parse', '--path-format=absolute', '--git-common-dir']);
        const rootCommon = git.run(root, ['rev-parse', '--path-format=absolute', '--git-common-dir']);
        const sameRepo = common.ok && rootCommon.ok && samePath(common.stdout, rootCommon.stdout);
        const evidence = [`chat row: execution_mode=${mode}, worktree_path=NULL`, `checkout Freebuff assigns to this chat: ${candidate}`, `owner record: ${claim.status === 'ok' ? `chat ${claim.value.threadId}, project ${claim.value.projectRoot}` : claim.status}`, `branch: ${head.ok ? head.stdout : 'none (detached HEAD)'}`, `same repository as project: ${sameRepo ? 'yes' : `no (${common.stdout || common.stderr} vs ${rootCommon.stdout || rootCommon.stderr})`}`];
        if (claimOk && head.ok && head.stdout && sameRepo) {
          S.add({ severity: 'error', area, key: `lost-wt:${t.id}`, title: `Chat lost its link to its worktree: ${label(t)}`, detail: 'This chat ran in its own Git worktree on this computer, and that checkout is still on disk, but the local chat record no longer points at it. Freebuff therefore runs the chat in the main project folder, whose identity differs from the one the chat was started with, and shows "The local checkout changed; reconnect the original folder" — even though nothing was moved. Re-opening the project folder does not fix this.', evidence,
            steps: ['Quit Freebuff completely (also from the system tray).', 'Run the repair tool with --fix. It re-links the chat to its checkout exactly the way Freebuff itself does when it first imports such a chat (it sets the chat to worktree mode with that folder and branch). The database is backed up first.', 'Start Freebuff and open the chat again.'],
            fix: relinkWorktreeFix(t, candidate, head.stdout) });
        } else {
          S.add({ severity: 'warn', area, key: `lost-wt-unsafe:${t.id}`, title: `Chat may have lost its worktree link, but the checkout can't be verified: ${label(t)}`, detail: 'A checkout exists where this chat\'s worktree would be, but it is not provably this chat\'s (different owner, different repository, or no branch). The repair tool will not change anything.', evidence, steps: ['Send this report to Freebuff support.'] });
        }
      }
    }
    if (target === 'cloud' && t.cloud_account_id && S.accountId && t.cloud_account_id !== S.accountId) S.add({ severity: 'warn', area, key: `acct:${t.id}`, title: `Chat belongs to another account: ${label(t)}`, detail: 'Opening it gives "This chat belongs to another account or environment".', evidence: [`chat account ${short(t.cloud_account_id)}…, current ${short(S.accountId)}…`], steps: ['Sign in with the account that created the chat.'] });
    if (t.cloud_api_host && t.cloud_api_host !== API_HOST) S.add({ severity: 'warn', area, title: `Chat was created against another server: ${label(t)}`, evidence: [t.cloud_api_host], detail: 'It cannot be opened with the regular Freebuff service.' });
    if (t.cloud_handoff_pending || t.local_handoff_pending) S.add({ severity: 'warn', area, key: `handoff:${t.id}`, title: `Chat has an unfinished ${t.cloud_handoff_pending ? 'move to Cloud' : 'move to this computer'}: ${label(t)}`, detail: 'Until it completes, the chat refuses local tools ("Finish the pending chat transfer before using local tools").', steps: ['Open the chat in Freebuff and use Retry in the location picker beside the model. Keep Freebuff open until it finishes.'] });
    const c = t.db.conflicts?.find((x) => x.thread_id === t.id);
    if (c) S.add({ severity: 'info', area, title: `${c.n} unresolved file conflict(s) from moving a chat back: ${label(t)}`, detail: 'Changing where the chat runs is blocked until resolved ("Resolve the remaining file changes before changing runtime").', steps: ['Open the chat; Freebuff lists the files to resolve.'] });
    if (t.project_path && root && !samePath(t.project_path, root) && isDir(t.project_path)) S.add({ severity: 'info', area, title: `Chat recorded under a different folder path: ${label(t)}`, evidence: [`chat: ${t.project_path}`, `database: ${root}`] });
    if (['running', 'queued'].includes(t.turn_state) && !S.appRunning) S.add({ severity: 'info', area, title: `Chat was interrupted mid-turn: ${label(t)}`, detail: 'Freebuff was closed or crashed while it was working. It marks the turn as interrupted when it next starts; you can continue the chat normally.' });
  }
  const orphans = (S.worktrees ?? []).filter((w) => w.ours && !w.legacy && w.claim?.threadId && !threads.some((t) => t.id === w.claim.threadId));
  if (orphans.length) S.add({ severity: 'info', area: 'Worktrees', title: `${orphans.length} worktree(s) belong to chats that no longer exist`, detail: 'Freebuff cleans these up over time. They only use disk space; uncommitted work in them is still on disk.', evidence: orphans.map((w) => `${w.path}${w.size ? ` (${fmtBytes(w.size.bytes)})` : ''}`) });
  S.inventory.threads = threads.map((t) => ({ id: t.id, title: opts.hideTitles ? undefined : truncate(t.title, 60), project: basename(t.db.projectPath ?? t.project_path ?? '?'), where: t.execution_target ?? 'local', mode: t.execution_mode, worktree: t.worktree_path ?? null, branch: t.branch ?? null, messages: t.messages, state: t.turn_state, updated: t.updated_at }));
  if (checked && !S.findings.some((f) => f.area === area && (f.severity === 'error' || f.severity === 'warn'))) S.ok(area, `${checked} chat(s) checked: worktrees, links and transfers look consistent`);
}

function editState(fx, P, mutate) {
  fx.backupFile(P.statePath);
  const cur = JSON.parse(readFileSync(P.statePath, 'utf8'));
  mutate(cur);
  const tmp = `${P.statePath}.frt-tmp`;
  writeFileSync(tmp, JSON.stringify(cur, null, 2));
  renameRetry(tmp, P.statePath);
}

function checkCloudRouting({ P, S }) {
  const area = 'Local vs Cloud';
  const st = S.state ?? {};
  const prefs = st.uiPrefs ?? {};
  const grants = Array.isArray(st.deviceReconnectGrants) ? st.deviceReconnectGrants : [];
  const registered = [];
  for (const p of S.projectsList ?? []) {
    const saved = st.projects?.[p.path] ?? {};
    if (p.location !== 'local') continue;
    const db = (S.dbs ?? []).find((d) => d.projectPath && samePath(d.projectPath, p.path));
    const threads = db?.threads ?? [];
    const cloudRuns = threads.filter((t) => t.execution_target === 'cloud' || t.next_execution_target === 'cloud');
    if (saved.deviceCloud || saved.cloudProjectId) registered.push(`${p.name}${saved.deviceCloud ? ' (enabled for Cloud/web chats)' : ''}`);
    const noFolderProject = saved.noFolder === true || within(p.path, join(P.profileDir, 'local-projects'));
    if (saved.defaultLocation === 'cloud' && saved.cloudPolicy !== 'never' && !noFolderProject) {
      S.add({ severity: 'error', area, key: `cloud-default:${p.path}`, title: `New chats in "${p.name}" start in Cloud, not on this computer`, detail: `This project's default run location is Cloud. Chats then run on Freebuff's servers and use Cloud credits; they can only see your files while Freebuff Desktop keeps the folder connected ("Your folder isn't connected to Freebuff yet. Keep Freebuff Desktop open and try again in a moment."), and they show up on the web app.${cloudRuns.length ? ` ${cloudRuns.length} chat(s) in this project are set to run in Cloud.` : ''}`,
        evidence: [`state.json projects[${p.path}].defaultLocation = "cloud"`, ...cloudRuns.slice(0, 8).map((t) => `chat ${short(t.id)} "${truncate(t.title, 40)}": runs in ${t.execution_target}, next run in ${t.next_execution_target ?? t.execution_target}`)],
        steps: ['Run the repair to make new chats start on this computer (Local) again.', 'For existing chats: open the chat and pick "Local" in the location picker beside the model.'],
        fix: { id: `cloud-default:${p.path}`, title: `Make new chats in "${p.name}" start on this computer`, risk: 'low — changes one project setting in state.json (backed up)', apply: (fx) => { editState(fx, P, (s) => { s.projects[p.path].defaultLocation = 'local'; }); fx.log(`projects[${p.path}].defaultLocation = "local"`); } } });
    } else if (cloudRuns.length) {
      S.add({ severity: 'info', area, key: `cloud-chats:${p.path}`, title: `${cloudRuns.length} chat(s) in "${p.name}" run in Cloud`, detail: 'These chats run on Freebuff\'s servers and use Cloud credits. They reach your local files only through a live folder connection from Freebuff Desktop.', evidence: cloudRuns.slice(0, 8).map((t) => `chat ${short(t.id)} "${truncate(t.title, 40)}"`), steps: ['To run one on this computer instead: open it and choose "Local" in the location picker beside the model.'] });
    }
    if (cloudRuns.length && p.exists) {
      const ok = grants.some((g) => g.accountId === S.accountId && g.installId === st.installId && samePath(g.path, p.path));
      if (!ok) S.add({ severity: 'error', area, key: `no-connection:${p.path}`, title: `Cloud chats in "${p.name}" cannot reach your files`, detail: 'There is no valid folder approval for this project on this computer, so chats running in Cloud get "Your folder isn\'t connected to Freebuff yet. Keep Freebuff Desktop open and try again in a moment." and cannot read files or use your local skills.', evidence: [p.path], steps: ['In Freebuff Desktop choose "Open local folder" and select this project folder, and keep Desktop running while the chat works.', 'Or switch the chat to "Local" so it runs on this computer.'] });
    }
  }
  if (prefs.cloudPresync === true) S.add({ severity: 'warn', area, key: 'cloud-presync', title: 'Background upload of your Git projects to Cloud is ON', detail: 'Freebuff uploads a snapshot of every local Git project (latest commit) to Cloud so Cloud chats can start faster. Projects set to "never use Cloud" are skipped.', evidence: ['state.json uiPrefs.cloudPresync = true'], steps: ['Turn it off in Freebuff settings, or run the repair.'],
    fix: { id: 'cloud-presync', title: 'Turn off background upload of projects to Cloud', risk: 'low — one setting in state.json (backed up)', apply: (fx) => { editState(fx, P, (s) => { s.uiPrefs = { ...(s.uiPrefs ?? {}), cloudPresync: false }; }); fx.log('uiPrefs.cloudPresync = false'); } } });
  if (prefs.mobileMirror === true) S.add({ severity: 'info', area, title: 'Mobile mirror is on', detail: 'Chats are mirrored so they can be followed from the web/phone.' });
  const uploads = join(P.profileDir, 'cloud-source-uploads');
  if (isDir(uploads)) { const s = dirStats(uploads, 20000); if (s.files) S.add({ severity: 'info', area, title: `Freebuff has uploaded project files to Cloud (${s.files} upload record(s), ${fmtBytes(s.bytes)})`, detail: 'These records are written when a project or chat is sent to Cloud (moving a chat to Cloud, background upload, or starting a Cloud chat).', evidence: [uploads] }); }
  if (registered.length) S.add({ severity: 'info', area, title: `${registered.length} local project(s) are registered with Freebuff Cloud`, detail: 'This is why they appear on the web app. Registering sends the project\'s name and ID; files are only uploaded when a chat runs in Cloud or background upload is on.', evidence: registered });
}

function parseSkill(file) {
  const text = readText(file);
  if (text === null) return { error: 'SKILL.md is missing' };
  const fm = text.replace(/^﻿/, '').match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!fm) return { error: 'SKILL.md has no front matter (--- name / description --- block at the top)' };
  const field = (k) => { const m = fm[1].match(new RegExp(`^${k}:\\s*(.*)$`, 'm')); if (!m) return null; let v = m[1].trim(); if (/^[>|][-+]?$/.test(v)) { const rest = fm[1].slice(fm[1].indexOf(m[0]) + m[0].length).split(/\r?\n/).slice(1); v = rest.filter((l) => /^\s+\S/.test(l)).map((l) => l.trim()).join(' '); } return v.replace(/^["']|["']$/g, ''); };
  const name = field('name'), description = field('description');
  if (!name) return { error: 'front matter has no "name:"' };
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(name) || name.length > 64) return { name, error: `name "${truncate(name, 40)}" is invalid (use lowercase letters, digits and single hyphens, max 64 characters)` };
  if (!description) return { name, error: 'front matter has no "description:"' };
  return { name, description };
}
function checkSkills({ P, S }) {
  const area = 'Skills';
  const roots = (S.projectsList ?? []).filter((p) => p.exists).map((p) => ({ label: `project "${p.name}"`, dir: p.path }));
  const places = [{ label: 'your home folder', dir: P.home }, ...roots];
  const found = [], seen = new Set();
  for (const { label, dir } of places) {
    for (const base of ['.agents', '.claude', '.freebuff']) {
      const right = join(dir, base, 'skills');
      for (const wrong of ['skill', 'Skills', 'SKILLS', '_skills']) {
        const w = join(dir, base, wrong);
        if (!isDir(w) || (IS_WIN || IS_MAC) && wrong.toLowerCase() === 'skills') continue;
        const kids = listDir(w).filter((e) => e.isDirectory()).map((e) => e.name);
        if (!kids.length) continue;
        const clash = kids.filter((k) => existsSync(join(right, k)));
        S.add({ severity: 'error', area, key: `skill-dir:${w}`, title: `Skills folder in ${label} is named "${base}/${wrong}" — Freebuff only reads "${base}/skills"`, detail: `Freebuff loads skills from .agents/skills, .claude/skills and .freebuff/skills (in your home folder and in each project). The ${kids.length} skill(s) in "${wrong}" are invisible to it.`, evidence: [w, ...kids.slice(0, 10).map((k) => `  ${k}`)],
          steps: [`Rename the folder "${wrong}" to "skills" (or run the repair).`],
          fix: clash.length ? undefined : { id: `skill-dir:${w}`, title: `Rename ${base}/${wrong} to ${base}/skills in ${label}`, risk: 'low — moves the skill folders; nothing is deleted', apply: (fx) => { if (!isDir(right)) { renameRetry(w, right); fx.manifest.entries.push({ action: 'renamed', original: w, now: right }); fx.save(); } else { for (const k of kids) { renameRetry(join(w, k), join(right, k)); fx.manifest.entries.push({ action: 'renamed', original: join(w, k), now: join(right, k) }); fx.save(); } if (!listDir(w).length) { rmSync(w, { recursive: true, force: true }); fx.manifest.entries.push({ action: 'removed-empty-dir', original: w }); fx.save(); } } fx.log(`${w} → ${right}`); } } });
      }
      for (const e of listDir(right).filter((x) => x.isDirectory() || x.isSymbolicLink())) {
        const skillDir = join(right, e.name);
        if (seen.has(normPath(canonical(skillDir)))) continue; seen.add(normPath(canonical(skillDir)));
        const r = parseSkill(join(skillDir, 'SKILL.md'));
        found.push({ where: `${label}: ${base}/skills/${e.name}`, ...r });
        if (r.error) S.add({ severity: 'warn', area, title: `Skill "${e.name}" in ${label} is not loaded`, detail: `Freebuff skips it: ${r.error}.`, evidence: [join(skillDir, 'SKILL.md')], steps: ['Fix the SKILL.md front matter, for example:\n---\nname: my-skill\ndescription: What it does and when to use it.\n---'] });
      }
    }
  }
  S.inventory.skills = found.map((f) => `${f.where} — ${f.error ? `NOT LOADED: ${f.error}` : f.name}`);
  const names = found.filter((f) => f.name && !f.error).map((f) => f.name);
  const dups = [...new Set(names.filter((n, i) => names.indexOf(n) !== i))];
  if (dups.length) S.add({ severity: 'info', area, title: `${dups.length} skill name(s) exist in more than one folder`, detail: 'Only one copy of each name is used; edits to the other copy have no effect.', evidence: dups });
  if (found.length && !found.some((f) => f.error)) S.ok(area, `${found.length} skill(s) found and valid`);
  if (!found.length) S.add({ severity: 'info', area, title: 'No skills found in this computer\'s skill folders', detail: 'Looked in .agents/skills, .claude/skills and .freebuff/skills in your home folder and every project.' });
}

function checkThreadDirs({ P, S }) {
  const area = 'Chats';
  for (const p of S.projectsList ?? []) {
    const saved = S.state?.projects?.[p.path] ?? {};
    const noFolder = saved.noFolder === true || (saved.location === 'cloud' && saved.cloudProjectId === null) || within(p.path, join(P.profileDir, 'local-projects'));
    if (!noFolder || !p.exists) continue;
    const db = (S.dbs ?? []).find((d) => d.projectPath && samePath(d.projectPath, p.path));
    const missing = (db?.threads ?? []).filter((t) => !t.sidebar_archived_at).map((t) => ({ t, dir: join(p.path, 'threads', sha(t.id)) })).filter((x) => !isDir(x.dir));
    if (!missing.length) continue;
    S.add({ severity: 'error', area, key: `thread-dirs:${p.path}`, title: `${missing.length} chat folder(s) missing in "${p.name}"`, detail: `Chats in a project without its own folder each get a private folder. These were deleted (by a cleanup tool, antivirus, a sync tool or manually), so opening the chat fails with "ENOENT: no such file or directory, lstat '…\\threads\\<id>'". Files the chat created there are gone; the conversation itself is intact.`,
      evidence: missing.slice(0, 10).map((x) => `"${truncate(x.t.title, 40)}" → ${x.dir}`), steps: ['Run the repair: it recreates the empty folders so the chats open again.'],
      fix: { id: `thread-dirs:${p.path}`, title: `Recreate ${missing.length} missing chat folder(s) in "${p.name}"`, risk: 'none — creates empty folders', apply: (fx) => { for (const x of missing) { mkdirSync(x.dir, { recursive: true }); fx.recordCreated(x.dir); fx.log(`created ${x.dir}`); } } } });
  }
}

function checkRefunds({ P, S }) {
  const area = 'Credits';
  const j = readJson(`${P.statePath}.session-refunds.json`);
  if (j.status !== 'ok' || !Array.isArray(j.value)) return;
  const by = (s) => j.value.filter((e) => e?.status === s);
  const open = [...by('pending'), ...by('retrying'), ...by('unreported')];
  const refunded = by('settled').filter((e) => (e.freebucks ?? 0) > 0);
  S.inventory.refunds = { entries: j.value.length, open: open.length, refunded: refunded.length, refundedFreebucks: refunded.reduce((s, e) => s + (e.freebucks ?? 0), 0) };
  if (open.length) S.add({ severity: 'warn', area, title: `${open.length} unused-session refund(s) have not been confirmed yet`, detail: 'Freebuff refunds sessions that ended without being used. These claims are waiting to be confirmed by the server; Freebuff retries them while it runs and is signed in.', evidence: open.slice(0, 8).map((e) => `chat ${short(e.admission?.threadId)}: ${e.status}, ${iso(e.updatedAt)}`), steps: ['Keep Freebuff open and signed in with internet access for a few minutes so it can retry.', 'If they stay unconfirmed, send this report to support — it lists the affected sessions.'] });
  else if (j.value.length) S.ok(area, `${j.value.length} session refund record(s), all settled${refunded.length ? ` (${refunded.length} refunded)` : ''}`);
}

function checkGit({ S, P }) {
  const area = 'Git';
  const git = makeGit(S.install?.res);
  const roots = new Map();
  for (const p of S.projectsList ?? []) if (p.exists && p.location === 'local' && !p.managed) roots.set(normPath(p.path), { path: p.path, name: p.name });
  for (const t of S.threads ?? []) if (t.worktree_path && isDir(t.worktree_path)) roots.set(normPath(t.worktree_path), { path: t.worktree_path, name: `worktree of ${basename(t.db.projectPath ?? '')}`, worktree: true });
  S.gitInfo = [];
  let dubious = [];
  for (const { path, name, worktree } of roots.values()) {
    const r = git.run(path, ['rev-parse', '--path-format=absolute', '--git-dir', '--git-common-dir', '--show-toplevel']);
    const info = { path, name };
    S.gitInfo.push(info);
    if (!r.ok) {
      if (/dubious ownership/i.test(r.stderr)) { dubious.push(path); info.error = 'dubious ownership'; continue; }
      if (/not a git repository/i.test(r.stderr)) { info.repo = false; continue; }
      info.error = r.stderr || r.error; S.add({ severity: 'warn', area, title: `Git fails in ${name}`, evidence: [path, truncate(r.stderr || r.error, 300)] }); continue;
    }
    const [gitDir, commonDir, top] = r.stdout.split(/\r?\n/).map((x) => (x ? resolve(x) : x));
    Object.assign(info, { repo: true, gitDir, commonDir, top });
    if (!worktree && top && !samePath(top, path)) S.add({ severity: 'info', area, title: `"${name}" is a subfolder of a Git repository`, detail: 'Worktree chats need the project folder to be the repository root; Freebuff offers only "Local" for this project.', evidence: [`project: ${path}`, `repository root: ${top}`] });
    for (const lockName of ['index.lock', 'HEAD.lock', 'config.lock']) {
      const lp = join(gitDir, lockName), ls = statSafe(lp);
      if (!ls) continue;
      const gitRunning = (S.procs ?? []).some((p) => p.kind === 'git');
      const stale = Date.now() - ls.mtimeMs > 10 * 60 * 1000 && !gitRunning;
      S.add({ severity: stale ? 'error' : 'info', area, key: `gitlock:${lp}`, title: `${stale ? 'Stale' : 'Active'} Git lock file in ${name}`, detail: stale ? `Git operations in this folder fail with "Unable to create '${lockName}': File exists" — usually left behind when Git or Freebuff was killed.` : 'A Git command may be running right now.', evidence: [`${lp} (${ago(ls.mtimeMs)})`],
        steps: stale ? ['Run the repair tool with --fix to remove it (it is moved to the backup folder), or delete the file by hand while no Git command is running.'] : [], fix: stale ? { id: `gitlock:${lp}`, title: `Remove stale ${lockName} in ${name}`, risk: 'low', requires: 'no git process running', apply: (fx) => fx.moveAside(lp) } : undefined });
    }
    if (!worktree) {
      const wl = git.run(path, ['worktree', 'list', '--porcelain']);
      if (wl.ok) {
        const blocks = wl.stdout.split(/\r?\n\r?\n/).map((b) => Object.fromEntries(b.split(/\r?\n/).map((l) => { const i = l.indexOf(' '); return i < 0 ? [l, true] : [l.slice(0, i), l.slice(i + 1)]; })));
        info.worktrees = blocks.filter((b) => b.worktree);
        const prunable = info.worktrees.filter((b) => b.prunable !== undefined || (b.worktree && !existsSync(b.worktree)));
        if (prunable.length) S.add({ severity: 'info', area, title: `${prunable.length} registered worktree(s) of "${name}" are missing on disk`, detail: 'Git still lists them. If a chat used one of them, that chat cannot continue (see the Chats section). Do NOT run "git worktree prune" if you plan to restore the folder.', evidence: prunable.map((b) => `${b.worktree}${b.branch ? ` (${String(b.branch).replace('refs/heads/', '')})` : ''}`) });
      }
    }
  }
  if (dubious.length) S.add({ severity: 'error', area, key: 'git:dubious', title: `Git refuses ${dubious.length} folder(s): "dubious ownership"`, detail: 'The folder is owned by a different Windows user (common after copying from another PC, an external drive, or creating it as Administrator). Freebuff\'s Git calls fail there: no changes, branches or worktrees.',
    evidence: dubious, steps: ['Run the repair tool with --fix to mark these folders as trusted for your user (adds safe.directory to your global Git config).', `Or run for each folder: git config --global --add safe.directory "${(dubious[0] ?? '').replace(/\\/g, '/')}"`, 'Or take ownership: right-click the folder → Properties → Security → Advanced → Owner → your user (apply to subfolders).'],
    fix: { id: 'git:dubious', title: `Trust ${dubious.length} folder(s) in your global Git config (safe.directory)`, risk: 'low — tells Git you trust these specific folders', confirm: true, apply: (fx) => { for (const d of dubious) { const r = git.run(P.home, ['config', '--global', '--add', 'safe.directory', d.replace(/\\/g, '/')]); if (!r.ok) throw new Error(r.stderr || r.error); fx.log(`git config --global --add safe.directory ${d.replace(/\\/g, '/')}`); } fx.note('To undo: git config --global --unset-all safe.directory "<path>"'); } } });
  S.inventory.git = { ...(S.inventory.git ?? {}), repositories: S.gitInfo.map((g) => ({ path: g.path, repo: g.repo ?? false, error: g.error, worktrees: g.worktrees?.length })) };
}

function checkJournals({ P, S, opts }) {
  const area = 'Pending transfers';
  const accounts = [...(S.accounts?.keys() ?? []), S.accountId].filter(Boolean);
  const threads = S.threads ?? [];
  const index = new Map();
  for (const a of new Set(accounts)) for (const t of threads) {
    index.set(sha(JSON.stringify([API_HOST, a, t.id])), { t, kind: 'runtime' });
    index.set(sha(JSON.stringify([API_HOST, a, t.id, 'move'])), { t, kind: 'move' });
  }
  const label = (t) => (t ? `"${opts.hideTitles ? short(t.id) : truncate(t.title, 50)}"` : 'an unknown chat');
  const report = [];
  const dirs = [['hosted-runtime-transfers', 'a change of where a chat runs (Local ⇄ Worktree ⇄ Cloud)'], ['pending-cloud-handoffs', 'a move of a chat to the Cloud'], ['pending-local-handoffs', 'a move of a chat back to this computer'], ['local-chat-imports', 'an import of a chat'], ['pending-cloud-cleanup', 'Cloud cleanup']];
  for (const [d, what] of dirs) {
    const dir = join(P.profileDir, d);
    for (const e of listDir(dir)) {
      const key = e.name.replace(/\.json$/, '');
      const s = statSafe(join(dir, e.name));
      const hit = index.get(key);
      report.push({ dir: d, file: e.name, chat: hit ? `${short(hit.t.id)} ${opts.hideTitles ? '' : truncate(hit.t.title, 40)}`.trim() : null, kind: hit?.kind ?? null, age: s?.mtimeMs });
      if (d === 'pending-cloud-cleanup') continue;
      const old = s && Date.now() - s.mtimeMs > 60 * 60 * 1000;
      if (old) S.add({ severity: 'warn', area, title: `Unfinished ${what} for ${label(hit?.t)}`, detail: `Started ${ago(s.mtimeMs)} and never completed (Freebuff was closed, crashed or lost the network). The chat keeps refusing other location changes ("Retry the pending runtime change before choosing another location").`, evidence: [join(dir, e.name)], steps: ['Open that chat in Freebuff, open the location picker beside the model and choose the same location again (Retry). Keep Freebuff open until it finishes.', 'If Retry keeps failing, send this report to support. Do not delete the file: it records what has already been transferred.'] });
    }
  }
  const ops = join(`${P.statePath}.device-operations`);
  if (isDir(ops)) { const st = dirStats(ops, 50000); S.inventory.deviceOperations = { dir: ops, files: st.files, bytes: st.bytes }; if (st.bytes > 512 << 20) S.add({ severity: 'warn', area, title: `Device operation journal is large (${fmtBytes(st.bytes)})`, detail: 'When it reaches its limit Freebuff stops running commands for Cloud chats on this computer ("Device receipt storage limit reached").', evidence: [ops] }); }
  S.inventory.journals = report;
  if (!report.filter((r) => r.dir !== 'pending-cloud-cleanup').length) S.ok(area, 'No unfinished chat transfers');
}

function checkDisks({ P, S }) {
  const area = 'Disk';
  const places = [['profile', P.profileDir], ['worktrees', P.worktreesDir], ...(S.projectsList ?? []).filter((p) => p.exists && !p.managed).map((p) => [`project ${p.name}`, p.path])];
  let drives = null;
  if (IS_WIN) {
    const r = sh('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '[System.IO.DriveInfo]::GetDrives() | ForEach-Object { $o=[ordered]@{Name=$_.Name;Type=[string]$_.DriveType;Format=$null;Free=$null;Total=$null}; try { $o.Format=$_.DriveFormat; $o.Free=$_.AvailableFreeSpace; $o.Total=$_.TotalSize } catch {}; [pscustomobject]$o } | ConvertTo-Json -Compress']);
    try { const v = JSON.parse(r.stdout || '[]'); drives = Array.isArray(v) ? v : [v]; } catch {}
  }
  const seen = new Set(); const rows = [];
  for (const [what, p] of places) {
    const target = existsSync(p) ? p : dirname(p);
    if (!existsSync(target)) continue;
    let info = {};
    if (drives) {
      const letter = canonical(target).slice(0, 3).toUpperCase();
      const d = drives.find((x) => String(x.Name).toUpperCase() === letter);
      if (d) info = { volume: d.Name, type: d.Type, fs: d.Format, free: d.Free, total: d.Total };
      else if (/^\\\\/.test(canonical(target))) info = { volume: canonical(target).split('\\').slice(0, 4).join('\\'), type: 'Network' };
    } else {
      try { const s = statfsSync(target); info = { volume: target, free: s.bavail * s.bsize, total: s.blocks * s.bsize, fsType: s.type }; } catch {}
    }
    rows.push({ what, path: p, ...info });
    const key = info.volume ?? target;
    if (seen.has(key)) continue; seen.add(key);
    if (info.free != null && info.free < 2 * 1024 ** 3) S.add({ severity: info.free < 512 * 1024 ** 2 ? 'error' : 'warn', area, title: `Low disk space on ${info.volume ?? target} (${fmtBytes(info.free)} free)`, detail: 'Freebuff writes chat databases, worktrees and journals; a full disk corrupts them or makes saves fail ("Check that the disk has free space").', steps: ['Free up at least a few GB of space.'] });
    if (info.type && /Network/i.test(info.type)) S.add({ severity: 'warn', area, title: `${what} is on a network drive (${info.volume})`, detail: 'Folder IDs on network drives can change after reconnecting, which breaks existing chats ("The local checkout changed"), and SQLite databases are unreliable there.', steps: ['Keep projects and the Freebuff profile on a local disk.'] });
    if (info.type && /Removable/i.test(info.type)) S.add({ severity: 'warn', area, title: `${what} is on a removable drive (${info.volume})`, detail: 'If the drive gets another letter or is unplugged, Freebuff loses the folder; reformatting changes the volume ID and breaks existing chats.' });
    if (info.fs && /^(FAT|FAT32|exFAT)$/i.test(info.fs)) S.add({ severity: 'warn', area, title: `${what} is on a ${info.fs} drive (${info.volume})`, detail: `${info.fs} has no stable folder IDs and no permissions; Freebuff identifies folders by ID, so chats can lose their folder, and Git worktrees/symlinks misbehave.`, steps: ['Use an NTFS (or ReFS/Dev Drive) volume for code projects.'] });
  }
  S.inventory.disks = rows;
}

const LOG_SIGNATURES = [
  { re: /already using this Desktop state profile|OrchestratorAlreadyRunning/i, sev: 'warn', title: 'Freebuff found another copy of itself running', fix: 'Quit every Freebuff window, end leftover bun.exe "orchestrator" processes in Task Manager, then start Freebuff once.' },
  { re: /\[statefile\].*unreadable JSON; moved to/i, sev: 'error', title: 'Freebuff reset a corrupted state.json', fix: 'See the Profile section for what was lost and how to recover it.' },
  { re: /not a database|SQLITE_CORRUPT|database disk image is malformed|integrity check failed/i, sev: 'error', title: 'A chat database was reported damaged', fix: 'See the Chat databases section; run the repair tool with --fix to rebuild it.' },
  { re: /dubious ownership/i, sev: 'error', title: 'Git refused a folder ("dubious ownership")', fix: 'See the Git section; --fix can trust the folder.' },
  { re: /\bENOSPC\b|no space left/i, sev: 'error', title: 'The disk ran out of space', fix: 'Free disk space.' },
  { re: /\b(EPERM|EACCES)\b|operation not permitted|access is denied/i, sev: 'warn', title: 'Freebuff was denied access to a file', fix: 'Antivirus, Controlled Folder Access or folder permissions blocked Freebuff. Allow Freebuff (Freebuff.exe and resources\\bun\\bun.exe) in your security software.' },
  { re: /\bEBUSY\b|resource busy or locked|being used by another process/i, sev: 'warn', title: 'A file was locked by another program', fix: 'Usually antivirus, a backup tool, OneDrive or an editor holding the file. Exclude your projects and the Freebuff profile from real-time scanning/sync.' },
  { re: /Illegal instruction|SIGILL|0xC000001D|STATUS_ILLEGAL_INSTRUCTION/i, sev: 'info', title: 'The fast Bun runtime crashed on this CPU', fix: 'Freebuff switches to the baseline runtime automatically. If it keeps crashing, reinstall Freebuff.' },
  { re: /The local checkout changed; reconnect the original folder/, sev: 'error', title: 'The reported error "The local checkout changed" occurred', fix: 'See the Chats and Folder approvals sections for the exact chat and cause.' },
  { re: /could not be decrypted on this machine/i, sev: 'warn', title: 'Saved sign-in could not be decrypted', fix: 'Sign in again.' },
  { re: /UNABLE_TO_VERIFY_LEAF_SIGNATURE|SELF_SIGNED_CERT|CERT_HAS_EXPIRED|unable to get local issuer|certificate/i, sev: 'warn', title: 'Secure connections failed certificate checks', fix: 'A proxy or antivirus "HTTPS scanning" is intercepting connections. Turn off HTTPS/SSL scanning for freebuff.com and codebuff.com, or ask IT to allow them.' },
  { re: /\b(ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ECONNRESET|ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT)\b/, sev: 'info', title: 'Network connection failures were logged', fix: 'Check your internet connection, VPN and firewall.' },
  { re: /shares this folder's project id/i, sev: 'info', title: 'A copied project folder got a new identity', fix: 'Open the original folder to see its chats.' },
  { re: /could not lock the state profile/i, sev: 'warn', title: 'Freebuff ran without its profile lock', fix: 'Make sure the profile folder is writable and not in a synced location.' },
  { re: /Device enrollment changed|device enrollment changed/i, sev: 'warn', title: 'The device enrollment changed', fix: 'Choose "Open local folder" again for the project.' },
  { re: /Local project identity changed|The local folder changed|The enrolled folder changed|Device folder was replaced/i, sev: 'warn', title: 'A project folder\'s identity changed', fix: 'See the Folder approvals section.' },
  { re: /\[orchestrator\] could not create stderr log/i, sev: 'warn', title: 'Freebuff could not write its log file', fix: 'Check permissions of the logs folder.' },
];
function checkLogs({ P, S }) {
  const area = 'Logs';
  const log = join(P.logsDir, 'orchestrator-stderr.log');
  const s = statSafe(log);
  if (!s) { S.add({ severity: 'info', area, title: 'No Freebuff log file found', detail: `Expected ${log}. Freebuff writes it each time it starts.` }); return; }
  const text = tailFile(log, 2 << 20) ?? '';
  const lines = text.split(/\r?\n/);
  const header = lines.slice(0, 6).filter(Boolean);
  S.inventory.log = { path: log, size: s.size, modified: s.mtimeMs, header, restarts: (text.match(/^\[restart \d+\]/gm) ?? []).length };
  const hits = [];
  for (const sig of LOG_SIGNATURES) {
    const matching = lines.filter((l) => sig.re.test(l));
    if (matching.length) hits.push({ sig, count: matching.length, last: matching[matching.length - 1] });
  }
  S.logHits = hits;
  for (const h of hits) S.add({ severity: h.sig.sev === 'error' ? 'warn' : h.sig.sev, area, title: `Log: ${h.sig.title} (${h.count}×)`, detail: 'Found in the log of the most recent Freebuff session.', evidence: [truncate(h.last.trim(), 400)], steps: [h.sig.fix] });
  if (S.inventory.log.restarts) S.add({ severity: 'warn', area, title: `Freebuff's background service crashed and restarted ${S.inventory.log.restarts}× in the last session`, detail: 'See the log excerpt at the end of this report for the crash output.', steps: ['If this repeats, send this report to support.'] });
  S.logTail = lines.slice(-60).join('\n');
  if (!hits.length) S.ok(area, `Latest log (${ago(s.mtimeMs)}) has no known problem signatures`);
}

function checkCrashes({ P, S }) {
  const area = 'Crash reports';
  const dirs = [join(P.userData, 'Crashpad', 'reports'), join(P.userData, 'Crashpad', 'completed'), join(P.userData, 'Crashpad', 'pending')];
  const dumps = [];
  for (const d of dirs) for (const e of listDir(d)) if (/\.dmp$/i.test(e.name)) { const s = statSafe(join(d, e.name)); if (s) dumps.push({ path: join(d, e.name), at: s.mtimeMs }); }
  const recent = dumps.filter((d) => Date.now() - d.at < 7 * 86400000);
  S.inventory.crashDumps = { total: dumps.length, lastWeek: recent.length, newest: dumps.length ? Math.max(...dumps.map((d) => d.at)) : null };
  if (recent.length >= 3) S.add({ severity: 'warn', area, title: `${recent.length} app crashes in the last 7 days`, detail: 'The Freebuff window (Electron) crashed. Frequent crashes are usually graphics-driver problems or antivirus injection.', evidence: recent.slice(-5).map((d) => `${iso(d.at)}: ${d.path}`), steps: ['Update your graphics driver.', 'If it persists, send this report and the newest .dmp file to support.'] });
  else if (recent.length) S.add({ severity: 'info', area, title: `${recent.length} app crash(es) in the last 7 days`, evidence: recent.map((d) => iso(d.at)) });
}

function checkInterface({ P, S }) {
  const area = 'Interface';
  if (S.install) {
    const ui = join(S.install.res, 'orchestrator', 'ui');
    const html = readText(join(ui, 'index.html'));
    if (html) {
      const refs = [...html.matchAll(/(?:src|href)="\.?\/?((?:assets|fonts)\/[^"?#]+)"/g)].map((m) => m[1]);
      const missing = refs.filter((r) => !isFile(join(ui, ...r.split('/'))));
      const empty = refs.filter((r) => statSafe(join(ui, ...r.split('/')))?.size === 0);
      if (missing.length || empty.length) S.add({ severity: 'error', area, title: 'Interface files are missing or empty', detail: 'Parts of the window (buttons, panels, whole screens) cannot load. Usually antivirus quarantine or an interrupted update.', evidence: [...missing.map((m) => `missing ${m}`), ...empty.map((m) => `empty ${m}`)], steps: ['Restore Freebuff files from your antivirus quarantine, or reinstall Freebuff (your chats are kept).'] });
      else S.ok(area, `Interface files complete (${refs.length} assets)`);
    }
  }
  const themeFile = readText(join(P.userData, 'theme'))?.trim();
  const prefs = S.state?.uiPrefs ?? {};
  S.inventory.interface = { themeFile: themeFile ?? '(default dark)', theme: prefs.theme ?? '(default)', appearance: prefs.appearance ? 'custom' : 'default', zoom: readText(join(P.userData, 'interface-zoom'))?.trim() ?? '(default)', explorerWidth: prefs.explorerWidth, explorerCollapsed: prefs.explorerCollapsed };
  if (themeFile !== undefined && themeFile !== null && !['dark', 'light', 'system'].includes(themeFile)) S.add({ severity: 'warn', area, title: 'The saved window theme is invalid', detail: `The theme file contains "${truncate(themeFile, 40)}", so Freebuff falls back to dark.`, evidence: [join(P.userData, 'theme')], steps: ['Choose a theme again in Freebuff settings, or run the repair.'], fix: { id: 'ui:theme', title: 'Reset the window theme file', risk: 'none', apply: (fx) => fx.moveAside(join(P.userData, 'theme')) } });
  if (prefs.theme && prefs.uiTheme === undefined && themeFile && prefs.theme !== themeFile) S.add({ severity: 'info', area, title: 'Window theme and app theme disagree', detail: `The app setting says "${prefs.theme}" but the window frame uses "${themeFile}". This can show a light frame around a dark app (or the reverse) until the theme is changed once.`, steps: ['Switch the theme in Freebuff settings to something else and back.'] });
  if (prefs.appearance && typeof prefs.appearance === 'object') {
    const wp = JSON.stringify(prefs.appearance).match(/"wallpaper[^"]*"\s*:\s*"([^"]+)"/i)?.[1];
    if (wp && !/^(https?:|data:|builtin|default)/.test(wp) && isAbsolute(wp) && !existsSync(wp)) S.add({ severity: 'warn', area, title: 'Custom theme wallpaper is missing', detail: 'The appearance uses a wallpaper file that no longer exists, so the theme shows a blank background.', evidence: [wp], steps: ['Pick the wallpaper again in Appearance settings, or choose another theme.'] });
  }
  const zoomRaw = readText(join(P.userData, 'interface-zoom'))?.trim();
  const zoom = Number(zoomRaw);
  if (zoomRaw && (!Number.isFinite(zoom) || zoom < -4 || zoom > 5 || (zoom > 0 && zoom < 0.3))) S.add({ severity: 'warn', area, title: `Interface zoom is extreme (${truncate(zoomRaw, 20)})`, detail: 'Buttons can end up off-screen or tiny.', steps: ['Press Ctrl+0 (Cmd+0 on Mac) in Freebuff to reset zoom, or run the repair.'], fix: { id: 'ui:zoom', title: 'Reset interface zoom', risk: 'none', apply: (fx) => fx.moveAside(join(P.userData, 'interface-zoom')) } });
  if (typeof prefs.explorerWidth === 'number' && (prefs.explorerWidth < 120 || prefs.explorerWidth > 4000)) S.add({ severity: 'info', area, title: `Side panel width is unusual (${prefs.explorerWidth}px)`, detail: 'The file/side panel may look missing or cover the chat.', steps: ['Drag the panel edge back, or toggle the side panel.'] });
  const sc = prefs.shortcuts && typeof prefs.shortcuts === 'object' ? Object.entries(prefs.shortcuts).filter(([, v]) => v === null) : [];
  if (sc.length) S.add({ severity: 'info', area, title: `${sc.length} keyboard shortcut(s) are switched off`, detail: 'If a shortcut "does nothing", it may have been unbound in settings.', evidence: sc.map(([k]) => k).slice(0, 20) });
  const caches = ['GPUCache', 'Code Cache', 'DawnGraphiteCache', 'DawnWebGPUCache', 'Shared Dictionary'].map((n) => join(P.userData, n)).filter(isDir);
  if (caches.length) {
    const size = caches.reduce((s, c) => s + dirStats(c, 20000).bytes, 0);
    S.add({ severity: 'info', area, key: 'ui:caches', title: `Display caches: ${fmtBytes(size)}`, detail: 'If the window is blank/white, flickers, shows an old interface after an update, or buttons do not respond, clearing these caches is safe — Freebuff rebuilds them. Chats, sign-in and settings are not affected.', evidence: caches, steps: ['Run the repair "Clear display caches" (Freebuff must be closed).'],
      fix: { id: 'ui:caches', title: 'Clear display caches (GPU / code caches)', risk: 'none — rebuilt automatically', confirm: true, apply: (fx) => { for (const c of caches) fx.moveAside(c); } } });
  }
  for (const f of ['Preferences', 'Local State']) {
    const p = join(P.userData, f);
    if (isFile(p) && readJson(p).status === 'corrupt') S.add({ severity: 'warn', area, title: `Window settings file "${f}" is damaged`, detail: 'Can cause lost window size, broken spell-check or devtools settings.', fix: { id: `ui:${f}`, title: `Reset "${f}"`, risk: 'low', apply: (fx) => fx.moveAside(p) } });
  }
  if (!S.appRunning) for (const db of S.dbs ?? []) for (const q of db.queue ?? []) if (['running', 'claimed', 'delivering'].includes(q.state)) S.add({ severity: 'info', area: 'Chats', title: `${q.n} queued message(s) were mid-delivery when Freebuff closed (${projectLabel(S, db)})`, detail: 'Freebuff re-delivers or marks them interrupted when it starts. If a chat looks stuck "thinking", stop it and send again.' });
}

async function checkNetwork({ S }) {
  const area = 'Network';
  const targets = [['Freebuff API', `${API_HOST}/`], ['Freebuff website', 'https://freebuff.com/']];
  const feed = S.install ? readText(join(S.install.res, 'app-update.yml'))?.match(/url:\s*(\S+)/)?.[1] : null;
  if (feed) targets.push(['update feed', `${feed.replace(/\/?$/, '/')}${IS_WIN ? 'latest.yml' : IS_MAC ? 'latest-mac.yml' : 'latest-linux.yml'}`]);
  S.inventory.network = [];
  for (const [what, url] of targets) {
    const t = Date.now();
    try {
      const r = await fetch(url, { redirect: what === 'update feed' ? 'follow' : 'manual', signal: AbortSignal.timeout(12000), headers: { 'user-agent': `frt/${DOCTOR_VERSION}` } });
      const body = what === 'update feed' && r.ok ? await r.text() : (await r.body?.cancel(), '');
      S.inventory.network.push({ what, url, status: r.status, ms: Date.now() - t });
      if (r.status >= 500) S.add({ severity: 'warn', area, title: `${what} answered with an error (${r.status})`, evidence: [url], steps: ['The service may be having problems; try again later.'] });
      if (what === 'update feed' && r.ok) {
        const latest = body.match(/^version:\s*['"]?([^'"\s]+)/m)?.[1];
        S.inventory.latestVersion = latest;
        if (latest && S.install?.version && latest !== S.install.version) S.add({ severity: 'warn', area: 'Installation', title: `An update is available: ${S.install.version} → ${latest}`, detail: 'Many problems are fixed in newer versions.', steps: ['Restart Freebuff to install the update, or download the latest version from https://freebuff.com.'] });
        else if (latest) S.ok('Installation', `Freebuff is up to date (${latest})`);
      }
    } catch (e) {
      const msg = `${e.cause?.code ?? e.code ?? ''} ${e.message}`.trim();
      S.inventory.network.push({ what, url, error: msg });
      const tls = /cert|self.signed|issuer|TLS|SSL/i.test(msg);
      S.add({ severity: 'warn', area, title: `Cannot reach the ${what}`, detail: tls ? 'The secure connection was intercepted (certificate problem). Typical cause: antivirus HTTPS scanning or a corporate proxy.' : 'Freebuff needs this connection for sign-in, Cloud chats and updates.', evidence: [`${url}: ${msg}`],
        steps: tls ? ['Turn off HTTPS/SSL scanning for freebuff.com and codebuff.com in your antivirus, or ask IT to allow them.'] : ['Check your internet connection, VPN, proxy and firewall. Allow Freebuff.exe and bun.exe through the firewall.'] });
    }
  }
  if (S.inventory.network.every((n) => n.status && n.status < 500)) S.ok(area, 'Freebuff servers are reachable');
}

const KNOWN_ERRORS = [
  { re: /isn.t connected to Freebuff yet|Keep Freebuff Desktop open and try again/i, title: 'Your folder isn\'t connected to Freebuff yet', meaning: 'The chat is running in Freebuff Cloud, not on this computer. Cloud chats can only read your files and local skills through a live connection from Freebuff Desktop to the project folder, and that connection is missing.',
    causes: ['The project is set to start new chats in Cloud (the repair tool can switch it back to Local).', 'The folder was never approved on this computer ("Open local folder"), or the approval no longer matches the folder.', 'Freebuff Desktop was closed, asleep or offline while the Cloud chat ran.'],
    fixes: ['To work locally: open the chat and choose "Local" in the location picker beside the model; run the repair tool to make new chats start locally.', 'To keep using Cloud: in Freebuff Desktop choose "Open local folder" for the project and keep Desktop open.'], areas: ['Local vs Cloud', 'Folder approvals', 'Skills'] },
  { re: /ENOENT[^]*[\\/]threads[\\/][0-9a-f]{64}/i, title: 'ENOENT … local-projects\\…\\threads\\<id>', meaning: 'A chat in a project that has no folder of its own keeps its files in a private folder named after the chat. That folder was deleted, so the chat cannot open.', causes: ['A cleanup tool, antivirus, OneDrive/Dropbox, or manual deletion removed it.'], fixes: ['Quit Freebuff and run the repair tool: it recreates the folder so the chat opens again (files that were in it are gone; the conversation is intact).'], areas: ['Chats'] },
  { re: /skill/i, title: 'Skills not found / not usable', meaning: 'Freebuff reads skills from .agents/skills, .claude/skills and .freebuff/skills, in your home folder and in each project. Each skill is a folder with a SKILL.md that starts with name/description front matter.', causes: ['The folder is named "skill" instead of "skills".', 'SKILL.md is missing or its front matter is invalid.', 'The chat runs in Cloud and cannot reach this computer\'s folders.'], fixes: ['See the Skills and Local vs Cloud sections of this report.'], areas: ['Skills', 'Local vs Cloud'] },
  { re: /credit|refund|freebucks|subscription|charged/i, title: 'Credits used without a working chat', meaning: 'Freebuff refunds sessions that ended unused; this computer keeps a journal of those refund claims.', causes: ['Chats ran in Cloud (Cloud runs use credits) while your files were unreachable.', 'Refund claims not yet confirmed by the server.'], fixes: ['See the Credits and Local vs Cloud sections; send this report to support for a credit review.'], areas: ['Credits', 'Local vs Cloud'] },
  { re: /local checkout changed|reconnect the original folder/i, title: 'The local checkout changed; reconnect the original folder',
    meaning: 'The chat was started (from the web, phone or Cloud) to run in a specific folder on this computer. Freebuff fingerprints that folder by its real path, drive ID and folder ID. Now the folder Freebuff would use has a different fingerprint, so it refuses to run the chat there.',
    causes: ['The chat ran in its own worktree, and the local chat record lost its link to that worktree, so the main folder is used instead (happens without moving anything — the repair tool detects and repairs this).', 'The project or worktree folder was deleted and recreated at the same path (re-cloned, restored from backup, re-extracted, or recreated by OneDrive/Dropbox).', 'The folder was moved/renamed, or is on a network/removable drive whose IDs changed.'],
    fixes: ['Read the "Chats" and "Folder approvals" sections of this report — they name the affected chat and the exact cause.', 'If the repair tool offers the "re-link the chat to its worktree" repair: quit Freebuff, run with --fix, reopen the chat.', 'If the original folder still exists elsewhere, move it back to its original path and choose "Open local folder" for it.', 'If the original folder is gone, start a new chat in the current folder (the old chat history stays readable).'], areas: ['Chats', 'Folder approvals', 'Worktrees', 'Projects', 'Disk'] },
  { re: /folder is disconnected|Choose Open local folder to reconnect/i, title: 'This folder is disconnected. Choose Open local folder to reconnect it.', meaning: 'There is no valid saved approval to run Cloud chats in this project folder on this computer.', causes: ['First use on this computer, the approval was removed, the computer ID changed, or the folder identity changed.'], fixes: ['Choose "Open local folder" and select the project folder.'], areas: ['Folder approvals', 'Profile'] },
  { re: /local folder changed\. Choose it again|Local project identity changed|enrolled folder changed|Device folder was replaced/i, title: 'The local folder changed (choose it again / identity changed)', meaning: 'The folder at the approved path is not the same folder (different folder ID or drive) as when it was approved.', causes: ['Folder deleted and recreated, re-cloned, restored, or moved.'], fixes: ['Choose "Open local folder" again for the current folder. Existing chats bound to the old folder still need the original folder (see "The local checkout changed").'], areas: ['Folder approvals'] },
  { re: /device enrollment changed|Device enrollment changed|Device session is not enrolled/i, title: 'The device enrollment changed', meaning: 'This computer\'s registration for the project no longer matches.', causes: ['The computer ID in your profile changed (profile reset/corruption), or you signed in with another account.'], fixes: ['Choose "Open local folder" again.', 'Check the Profile section for a profile reset.'], areas: ['Profile', 'Sign-in', 'Folder approvals'] },
  { re: /belongs to another account or environment|Account changed\. Sign in again/i, title: 'This chat belongs to another account or environment', meaning: 'The chat was created while signed in to a different Freebuff account.', causes: ['You switched accounts.'], fixes: ['Sign in with the account that created the chat.'], areas: ['Sign-in', 'Chats'] },
  { re: /Cloud chat belongs to another local project|identity collides with another local thread/i, title: 'Cloud chat belongs to another local project', meaning: 'The chat is already recorded under a different local project folder.', causes: ['The same project was added twice (for example a copy and the original).'], fixes: ['Open the chat from the project it was started in.'], areas: ['Projects', 'Chat databases'] },
  { re: /asleep or unreachable|on its original computer first|on the computer it runs on/i, title: 'The chat runs on another computer', meaning: 'Freebuff believes the chat belongs to a different computer.', causes: ['It really runs on another computer.', 'Your computer ID changed because state.json was reset after corruption (see Profile).'], fixes: ['Open it on the original computer, or move it to Cloud there.', 'If the repair tool reports a profile reset, run --fix to restore the old computer ID.'], areas: ['Profile'] },
  { re: /Another copy of Freebuff has this project open|already using this Desktop state profile/i, title: 'Another copy of Freebuff is running', meaning: 'Only one Freebuff can use a profile/project at a time.', causes: ['A second window/instance, or a leftover background process after a crash.'], fixes: ['Quit Freebuff, end leftover bun.exe processes whose command line mentions orchestrator.js, start again.'], areas: ['Freebuff process'] },
  { re: /could not be read \(.*not a database|database .*could not be read|integrity check failed|malformed/i, title: 'Chat database could not be read', meaning: 'The SQLite database holding this project\'s chats is damaged.', causes: ['Crash/power loss while writing, disk errors, sync tools, antivirus.'], fixes: ['Quit Freebuff and run the repair tool with --fix to rebuild it from the readable data.'], areas: ['Chat databases'] },
  { re: /could not create its database in this folder|could not write its local thread database/i, title: 'Freebuff could not create/write its database', meaning: 'Writing failed.', causes: ['Disk full, no permission, synced/network folder.'], fixes: ['Free disk space; keep the profile and projects on a local disk outside OneDrive/Dropbox.'], areas: ['Disk', 'Profile'] },
  { re: /Retry the pending runtime change|Wait for this runtime change to finish|Finish the pending chat transfer/i, title: 'A runtime change / transfer is pending', meaning: 'Moving the chat between Local, Worktree and Cloud was interrupted.', causes: ['Freebuff was closed or lost network mid-transfer.'], fixes: ['Open the chat and choose the same location again (Retry). Keep Freebuff open until it completes.'], areas: ['Pending transfers', 'Chats'] },
  { re: /Resolve the remaining file changes/i, title: 'Resolve the remaining file changes before changing runtime', meaning: 'Files changed both locally and in Cloud.', causes: ['Continuing locally after Cloud edits.'], fixes: ['Open the chat; resolve the listed files.'], areas: ['Chats'] },
  { re: /multiple local databases for project identity/i, title: 'Multiple local databases for one project', meaning: 'Two database folders claim the same project identity, so Freebuff opens neither.', causes: ['A restored backup next to a newer copy.'], fixes: ['Run the repair tool with --fix (moves the empty duplicate aside) or send the report to support.'], areas: ['Chat databases'] },
  { re: /invalid project identity marker|could not read this project's identity marker/i, title: 'Invalid project identity marker', meaning: 'The .freebuff\\project-id file in the project is damaged or unreadable.', causes: ['Edited/merged by hand, or a sync/merge conflict.'], fixes: ['Run the repair tool with --fix, or delete .freebuff\\project-id so Freebuff re-links the folder to its history.'], areas: ['Chat databases'] },
  { re: /belongs to another thread/i, title: 'Worktree belongs to another thread', meaning: 'The checkout Freebuff wants to create for this chat is owned by another chat.', causes: ['Leftover worktree with the same short ID.'], fixes: ['Send the report to support; the Worktrees section lists the owner.'], areas: ['Worktrees'] },
  { re: /is not a git repository, so it cannot manage worktrees|Only a chat in a Git repository/i, title: 'Not a Git repository', meaning: 'Worktree features need the project folder to be the root of a Git repository.', causes: ['The project is not a Git repo, or Git cannot read it (dubious ownership).'], fixes: ['Run `git init` in the project, or fix Git ownership (see the Git section).'], areas: ['Git'] },
  { re: /Local folder is unavailable|The local folder could not connect/i, title: 'Local folder is unavailable / could not connect', meaning: 'The folder could not be opened, or registering it with the Freebuff service failed.', causes: ['Folder missing or not a folder; network problem; account lacks access.'], fixes: ['Check the folder exists; check the Network section; sign in again.'], areas: ['Projects', 'Network', 'Sign-in'] },
  { re: /native protocol 3|does not support device execution/i, title: 'Server/app protocol mismatch', meaning: 'This Freebuff is too old for the service.', causes: ['Outdated app.'], fixes: ['Update Freebuff.'], areas: ['Installation'] },
];
function explainError({ S }, message) {
  const hits = KNOWN_ERRORS.filter((k) => k.re.test(message));
  S.errorLookups = [...(S.errorLookups ?? []), { message, hits }];
  if (!hits.length) S.add({ severity: 'info', area: 'Error lookup', title: `No explanation known for: "${truncate(message, 120)}"`, detail: 'The full scan below still applies. Include the exact message when contacting support.' });
}

function relinkWorktreeFix(t, path, branch) {
  return { id: `relink-worktree:${t.id}`, title: `Re-link chat ${short(t.id)}… to its worktree ${path} (branch ${branch})`, risk: 'low — one database row; the database is backed up first',
    apply: (fx) => {
      fx.backupDb(t.db.dbPath);
      const db = openDb(t.db.dbPath);
      try {
        db.exec('PRAGMA busy_timeout = 5000');
        const now = Date.now();
        const r = db.query("UPDATE threads SET execution_mode = 'worktree', worktree_path = $p, branch = $b, updated_at = $now WHERE id = $id AND worktree_path IS NULL").run({ $p: path, $b: branch, $now: now, $id: t.id });
        if (r.changes !== 1) throw new Error(`expected to update 1 row, updated ${r.changes}`);
        const after = db.query('SELECT execution_mode, worktree_path, branch FROM threads WHERE id = $id').get({ $id: t.id });
        fx.log(`threads[${t.id}]: execution_mode=${after.execution_mode}, worktree_path=${after.worktree_path}, branch=${after.branch}`);
        db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
      } finally { db.close(); }
    } };
}
function markerFix(p, markerPath, oldRaw, entry) {
  return { id: `marker:${p.path}`, title: `Re-link "${p.name}" to its chat history (${short(entry.projectId)}…)`, risk: 'low — rewrites the one-line .freebuff/project-id file (backed up)',
    apply: (fx) => { if (oldRaw !== null) fx.backupFile(markerPath); else fx.recordCreated(markerPath); mkdirSync(dirname(markerPath), { recursive: true }); writeFileSync(markerPath, `${entry.projectId}\n`); fx.log(`${markerPath} = ${entry.projectId}`); } };
}
function dbRebuildFix(entry) {
  return { id: `db-rebuild:${entry.dir}`, title: `Rebuild the damaged chat database for ${entry.projectPath ? basename(entry.projectPath) : entry.name}`, risk: 'medium — the original is kept in the backup folder; rows SQLite cannot read are lost', confirm: true,
    apply: (fx) => {
      fx.backupDb(entry.dbPath);
      const tmp = `${entry.dbPath}.frt-rebuild-${Date.now()}`;
      const clean = () => { for (const s of ['', '-wal', '-shm', '-journal']) rmSync(`${tmp}${s}`, { force: true }); };
      const integrity = (p) => { const d = openDb(p); try { return d.query('PRAGMA integrity_check').all().map((r) => Object.values(r)[0]); } finally { d.close(); } };
      let how = 'VACUUM INTO', ok = null, stats = null;
      try {
        const src = openDb(entry.dbPath, { readonly: true });
        try { src.query('VACUUM INTO ?').run(tmp); } finally { src.close(); }
        ok = integrity(tmp);
      } catch (e) { fx.log(`VACUUM INTO failed (${e.message}); salvaging table by table`); }
      if (!(ok?.length === 1 && ok[0] === 'ok')) {
        clean(); how = 'salvage copy';
        stats = salvageCopy(entry.dbPath, tmp);
        ok = integrity(tmp);
      }
      if (!(ok.length === 1 && ok[0] === 'ok')) { clean(); throw new Error(`the rebuilt copy is still damaged (${ok.slice(0, 3).join('; ')}) — restore from a backup or contact support`); }
      for (const s of ['-wal', '-shm', '-journal']) { rmSync(`${entry.dbPath}${s}`, { force: true }); rmSync(`${tmp}${s}`, { force: true }); }
      renameRetry(tmp, entry.dbPath);
      fx.log(`rebuilt ${entry.dbPath} with ${how} (integrity ok)`);
      if (stats) for (const [t, s] of Object.entries(stats)) fx.log(`  ${t}: ${s.copied} row(s) copied${s.lost ? `, UNREADABLE parts skipped (${s.lost})` : ''}`);
    } };
}
function salvageCopy(srcPath, dstPath) {
  const q = (n) => `"${String(n).replace(/"/g, '""')}"`;
  const src = openDb(srcPath, { readonly: true });
  const dst = openDb(dstPath, { create: true });
  const stats = {};
  try {
    const objs = src.query('SELECT type, name, tbl_name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY rowid').all();
    const virtual = objs.filter((o) => o.type === 'table' && /^\s*CREATE\s+VIRTUAL\s+TABLE/i.test(o.sql)).map((o) => o.name);
    const isShadow = (n) => virtual.some((v) => n.startsWith(`${v}_`));
    const tables = objs.filter((o) => o.type === 'table' && !o.name.startsWith('sqlite_') && !isShadow(o.name));
    dst.exec('PRAGMA journal_mode = DELETE');
    dst.exec(`PRAGMA user_version = ${Number(src.query('PRAGMA user_version').get().user_version) || 0}`);
    dst.transaction(() => {
      for (const t of tables) dst.exec(t.sql);
      for (const o of objs.filter((x) => x.type === 'trigger')) dst.exec(o.sql);
    })();
    for (const t of tables.filter((x) => !virtual.includes(x.name))) {
      const cols = src.query(`PRAGMA table_info(${q(t.name)})`).all().map((c) => c.name);
      const ins = dst.prepare(`INSERT OR IGNORE INTO ${q(t.name)} (${cols.map(q).join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`);
      const s = { copied: 0, lost: '' };
      const lost = [];
      const batch = (from, limit) => src.query(`SELECT rowid AS "__rowid__", * FROM ${q(t.name)} WHERE rowid >= ? ORDER BY rowid LIMIT ${limit}`).all(from + 1);
      const readable = (x) => { try { src.query(`SELECT * FROM ${q(t.name)} WHERE rowid >= ? ORDER BY rowid LIMIT 1`).get(x); return true; } catch { return false; } };
      const put = (rows) => { dst.transaction(() => { for (const r of rows) ins.run(...cols.map((c) => r[c])); })(); s.copied += rows.length; };
      let after = -(2 ** 62), skips = 0;
      for (;;) {
        let rows;
        try { rows = batch(after, 500); } catch {
          for (;;) { let one; try { one = batch(after, 1); } catch { break; } if (!one.length) { rows = []; break; } put(one); after = one[0].__rowid__; }
          if (rows) break;
          let lo = after + 1, step = 1, hi = null;
          while (step <= 2 ** 52) { if (readable(after + step)) { hi = after + step; break; } lo = after + step; step *= 2; }
          if (hi === null || ++skips > 1000) { lost.push(`everything after rowid ${after}`); break; }
          while (hi - lo > 1) { const mid = Math.floor((lo + hi) / 2); if (readable(mid)) hi = mid; else lo = mid; }
          lost.push(`rowids ${after + 1}–${hi - 1}`); after = hi - 1; continue;
        }
        if (!rows.length) break;
        put(rows); after = rows[rows.length - 1].__rowid__;
      }
      s.lost = lost.join('; ');
      stats[t.name] = s;
    }
    for (const o of objs.filter((x) => x.type === 'index')) dst.exec(o.sql);
    dst.exec('PRAGMA journal_mode = WAL');
  } finally { src.close(); dst.close(); }
  return stats;
}
function salvageInstallIdFix(P, st, corrupt) {
  return { id: 'restore-install-id', title: `Restore the computer ID from before the profile reset (${short(st.installId)}… → ${short(corrupt.installId)}…)`, confirm: true,
    risk: 'medium — chats from before the reset become local again; chats started after the reset would look like they run on another computer. Folder approvals made after the reset must be redone (Open local folder).',
    apply: (fx) => {
      fx.backupFile(P.statePath);
      const cur = JSON.parse(readFileSync(P.statePath, 'utf8'));
      cur.installId = corrupt.installId;
      writeFileSync(P.statePath, JSON.stringify(cur, null, 2));
      fx.log(`state.json installId = ${corrupt.installId}`);
    } };
}

class Fixer {
  constructor(P, S) {
    this.P = P; this.S = S;
    this.dir = join(P.profileDir, 'frt-backups', new Date().toISOString().replace(/[:.]/g, '-'));
    this.manifest = { created: new Date().toISOString(), doctor: DOCTOR_VERSION, profile: P.statePath, entries: [] };
    this.lines = []; this.notes = [];
  }
  ensure() { mkdirSync(this.dir, { recursive: true }); }
  save() { this.ensure(); writeFileSync(join(this.dir, 'manifest.json'), JSON.stringify(this.manifest, null, 2)); }
  dest(p) { this.ensure(); const d = join(this.dir, 'files', `${this.manifest.entries.length}-${basename(p)}`); mkdirSync(dirname(d), { recursive: true }); return d; }
  backupFile(p) { const d = this.dest(p); cpSync(p, d, { recursive: true }); this.manifest.entries.push({ action: 'copied', original: p, backup: d }); this.save(); }
  backupDb(p) { for (const s of ['', '-wal', '-shm']) if (existsSync(`${p}${s}`)) this.backupFile(`${p}${s}`); this.manifest.entries.push({ action: 'db-sidecars', original: p }); this.save(); }
  moveAside(p) {
    const d = this.dest(p);
    try { renameRetry(p, d); } catch (e) {
      if (e.code !== 'EXDEV') throw e;
      cpSync(p, d, { recursive: true });
      try { rmSync(p, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 }); } catch (e2) { rmSync(d, { recursive: true, force: true }); throw e2; }
    }
    this.manifest.entries.push({ action: 'moved', original: p, backup: d }); this.save(); this.log(`moved ${p} → ${d}`);
  }
  recordCreated(p) { this.manifest.entries.push({ action: 'created', original: p }); this.save(); }
  log(s) { this.lines.push(s); }
  note(s) { this.notes.push(s); }
}

function restoreBackup(dir, P) {
  const m = readJson(join(dir, 'manifest.json'));
  if (m.status !== 'ok') die(`No readable manifest.json in ${dir}`);
  const lock = profileLockState(P.statePath);
  if (lock.state === 'held') die('Quit Freebuff completely before restoring.');
  const release = holdProfileLock(P.statePath);
  try {
    const entries = [...m.value.entries].reverse();
    const dbs = new Set(entries.filter((e) => e.action === 'db-sidecars').map((e) => e.original));
    for (const db of dbs) for (const s of ['-wal', '-shm']) rmSync(`${db}${s}`, { force: true });
    for (const e of entries) {
      if (e.action === 'copied' || e.action === 'moved') { rmSync(e.original, { recursive: true, force: true }); mkdirSync(dirname(e.original), { recursive: true }); cpSync(e.backup, e.original, { recursive: true }); console.log(`restored ${e.original}`); }
      if (e.action === 'created') { rmSync(e.original, { recursive: true, force: true }); console.log(`removed ${e.original}`); }
      if (e.action === 'removed-empty-dir') { mkdirSync(e.original, { recursive: true }); console.log(`recreated ${e.original}`); }
      if (e.action === 'renamed' && existsSync(e.now) && !existsSync(e.original)) { mkdirSync(dirname(e.original), { recursive: true }); renameRetry(e.now, e.original); console.log(`moved back ${e.original}`); }
    }
    console.log(`\nRestore complete from ${dir}. (Global Git config changes, if any, are not undone automatically; see the report's notes.)`);
  } finally { release(); }
}

async function ask(question) {
  if (!process.stdin.isTTY) return false;
  const a = typeof prompt === 'function' ? prompt(`${question} [y/N]`) : null;
  return /^y(es)?$/i.test(String(a ?? '').trim());
}

async function runFixes(S, P, opts) {
  const result = { applied: [], failed: [], skipped: [], backupDir: null, notes: [] };
  const fixes = S.fixes;
  if (!fixes.length) return result;
  if (appBlocks(profileLockState(P.statePath), runningProcesses(), S.install)) {
    result.blocked = 'Freebuff is running. Quit it completely (including the tray/menu-bar icon) and run the repair tool again to apply repairs.';
    return result;
  }
  let release;
  try { release = holdProfileLock(P.statePath); } catch (e) { result.blocked = `Could not take Freebuff's profile lock (${e.message}); is Freebuff starting?`; return result; }
  const fx = new Fixer(P, S);
  try {
    for (const f of fixes) {
      if (f.requires === 'no git process running' && runningProcesses().some((p) => p.kind === 'git')) { result.skipped.push({ fix: f, why: 'a Git process is running' }); continue; }
      let go = opts.yes && (!f.confirm || opts.yesAll);
      if (!go) {
        console.log(`\n  Repair: ${f.title}\n  Risk:   ${f.risk}`);
        go = await ask('  Apply this repair?');
        if (!go && opts.yes && f.confirm) result.skipped.push({ fix: f, why: 'needs explicit confirmation (not covered by --yes)' });
      }
      if (!go) { if (!result.skipped.some((s) => s.fix === f)) result.skipped.push({ fix: f, why: 'not confirmed' }); continue; }
      const before = fx.lines.length;
      try { await f.apply(fx); result.applied.push({ fix: f, log: fx.lines.slice(before) }); console.log('  ✔ applied'); }
      catch (e) { result.failed.push({ fix: f, error: e.message, log: fx.lines.slice(before) }); console.log(`  ✖ failed: ${e.message}`); }
    }
  } finally { release(); }
  if (fx.manifest.entries.length) { fx.save(); result.backupDir = fx.dir; }
  result.notes = fx.notes;
  return result;
}

function redactor(P, opts) {
  if (!opts.redact) return (s) => s;
  const homeVariants = [P.home, P.home.replace(/\\/g, '/'), IS_WIN ? P.home.replace(/\\/g, '\\\\') : null].filter(Boolean);
  const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const homeRe = new RegExp(homeVariants.map(esc).join('|'), IS_WIN ? 'gi' : 'g');
  return (s) => String(s)
    .replace(homeRe, IS_WIN ? '%USERPROFILE%' : '~')
    .replace(/([A-Za-z]:\\Users\\)[^\\\s"']+/g, '$1<user>').replace(/(\/(?:home|Users)\/)[^/\s"']+/g, '$1<user>')
    .replace(/\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g, '$1***@$2')
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/-]+=*/g, '$1<redacted>')
    .replace(/("?(?:token|authToken|password|secret)"?\s*[:=]\s*"?)[^"\s,}]{8,}/gi, '$1<redacted>');
}

function renderReport(S, P, opts, fixResult, verify) {
  const L = [];
  const env = S.inventory.environment ?? {};
  const sorted = [...S.findings].sort((a, b) => SEVERITY[a.severity] - SEVERITY[b.severity]);
  const problems = sorted.filter((f) => f.severity === 'error' || f.severity === 'warn');
  const fixable = S.fixes.length;
  L.push('# Freebuff Repair Tool report', '');
  L.push(`Generated ${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC by Freebuff Repair Tool ${DOCTOR_VERSION} in ${(S.elapsedMs / 1000).toFixed(1)}s. ${opts.redact ? 'Personal details (home folder, user name, e-mail) are masked.' : 'Not redacted.'} Sign-in tokens are never read into this report.`, '');
  L.push('| | |', '|---|---|');
  L.push(`| Freebuff | ${S.install ? `${S.install.version ?? '?'} at \`${S.install.dir}\`` : 'not found'} |`);
  L.push(`| System | ${mdEscape(env.os)} |`);
  L.push(`| Profile | \`${P.statePath}\` |`);
  L.push(`| Freebuff running | ${S.appRunning ? 'yes (scan was read-only)' : 'no'} |`);
  L.push(`| Folder identity rules | ${S.identitySource} |`);
  L.push('');
  L.push('## Summary', '');
  L.push(`| ${ICON.error} Errors | ${ICON.warn} Warnings | ${ICON.info} Notes | ${ICON.ok} Passed | Repairs available |`, '|---|---|---|---|---|');
  L.push(`| ${S.count('error')} | ${S.count('warn')} | ${S.count('info')} | ${S.count('ok')} | ${fixable} |`, '');

  if (S.errorLookups?.length) {
    L.push('## Your error message', '');
    for (const { message, hits } of S.errorLookups) {
      L.push(`> ${mdEscape(message)}`, '');
      if (!hits.length) { L.push('No known explanation; see the findings below.', ''); continue; }
      for (const k of hits) {
        L.push(`**${k.title}**`, '', k.meaning, '', '_Possible causes:_', ...k.causes.map((c) => `- ${c}`), '', '_What to do:_', ...k.fixes.map((c, i) => `${i + 1}. ${c}`), '');
        const rel = problems.filter((f) => k.areas.includes(f.area));
        L.push(rel.length ? `**Found on this computer:** ${rel.map((f) => `${ICON[f.severity]} ${f.title}`).join('; ')}` : '**Found on this computer:** nothing in the related areas — the cause may be in data the repair tool cannot see (the Cloud side of the chat). Include this report when contacting support.', '');
      }
    }
  }

  L.push('## What to do', '');
  if (!problems.length) L.push('No problems found. 🎉', '');
  else {
    let n = 1;
    if (fixable && !fixResult) L.push(`${n++}. **Quit Freebuff completely** (also from the system tray), then run the repair tool again with \`--fix\` to apply ${fixable} automatic repair(s). Every change is backed up first.`);
    for (const f of problems.slice(0, 12)) L.push(`${n++}. ${ICON[f.severity]} **${f.title}** — ${f.steps?.[0] ?? 'see details below.'}`);
    if (problems.length > 12) L.push(`${n++}. …and ${problems.length - 12} more below.`);
    L.push('');
  }

  if (fixResult) {
    L.push('## Repairs', '');
    if (fixResult.blocked) L.push(`**Not applied:** ${fixResult.blocked}`, '');
    for (const a of fixResult.applied) L.push(`- ✔ **${a.fix.title}**`, ...a.log.map((l) => `  - \`${l}\``));
    for (const a of fixResult.failed) L.push(`- ✖ **${a.fix.title}** — failed: ${a.error}`);
    for (const a of fixResult.skipped) L.push(`- ○ ${a.fix.title} — skipped (${a.why})`);
    if (fixResult.backupDir) L.push('', `Backups of everything changed: \`${fixResult.backupDir}\``, `Undo with: \`frt --restore "${fixResult.backupDir}"\``);
    for (const n of fixResult.notes ?? []) L.push(`- ${n}`);
    if (verify) L.push('', `**Re-check after repairs:** ${verify.count('error')} error(s), ${verify.count('warn')} warning(s) remaining${verify.count('error') ? `: ${verify.findings.filter((f) => f.severity === 'error').map((f) => f.title).join('; ')}` : ''}.`);
    L.push('');
  }

  L.push('## Findings', '');
  const groups = [['error', 'Errors'], ['warn', 'Warnings'], ['info', 'Notes']];
  let i = 0;
  for (const [sev, name] of groups) {
    const list = sorted.filter((f) => f.severity === sev);
    if (!list.length) continue;
    L.push(`### ${ICON[sev]} ${name} (${list.length})`, '');
    for (const f of list) {
      i++;
      L.push(`#### ${i}. ${f.title}`, '', `_Area: ${f.area}_`, '');
      if (f.detail) L.push(f.detail, '');
      if (f.evidence?.length) L.push('Evidence:', '', '```text', ...f.evidence.map(String), '```', '');
      if (f.steps?.length) L.push('How to fix:', '', ...f.steps.map((s, k) => `${k + 1}. ${s}`), '');
      if (f.fix) {
        const applied = fixResult?.applied.find((a) => a.fix === f.fix), failed = fixResult?.failed.find((a) => a.fix === f.fix);
        L.push(`Automatic repair: **${applied ? 'applied ✔' : failed ? `failed ✖ (${failed.error})` : 'available'}** — ${f.fix.title}. Risk: ${f.fix.risk}.`, '');
      }
    }
  }
  const passed = sorted.filter((f) => f.severity === 'ok');
  if (passed.length) L.push(`### ${ICON.ok} Passed (${passed.length})`, '', ...passed.map((f) => `- ${f.title}${f.detail ? ` — ${f.detail}` : ''}`), '');

  L.push('## Inventory', '');
  const det = (summary, body) => L.push(`<details><summary>${summary}</summary>`, '', ...body, '', '</details>', '');
  det('Environment', ['```json', JSON.stringify(S.inventory.environment, null, 2), '```']);
  if (S.inventory.installs) det(`Installations (${S.inventory.installs.length})`, S.inventory.installs.map((x) => `- \`${x.dir}\` — ${x.version ?? '?'} (${x.commit ?? 'no build info'}) — found via ${x.how}`));
  det('Sign-in', ['```json', JSON.stringify(S.inventory.auth ?? {}, null, 2), '```']);
  if (S.inventory.projects?.length) det(`Projects (${S.inventory.projects.length})`, ['| Name | Where | Path | Exists | Marker | Sync |', '|---|---|---|---|---|---|', ...S.inventory.projects.map((p) => `| ${mdEscape(p.name)} | ${p.location ?? '?'}${p.managed ? ' (app-managed)' : ''} | \`${mdEscape(p.path)}\` | ${p.exists ? 'yes' : '**no**'} | ${p.marker ? short(p.marker) : '—'} | ${p.sync ?? '—'} |`)]);
  if (S.inventory.databases?.length) det(`Chat databases (${S.inventory.databases.length})`, ['| Folder | Project | Size | WAL | Integrity | Chats |', '|---|---|---|---|---|---|', ...S.inventory.databases.map((d) => `| ${mdEscape(truncate(d.folder, 30))} | \`${mdEscape(d.project ?? '?')}\` | ${fmtBytes(d.size)} | ${fmtBytes(d.wal)} | ${d.integrity} | ${d.threads} |`)]);
  if (S.inventory.threads?.length) det(`Chats (${S.inventory.threads.length})`, ['| ID | Title | Project | Runs | Mode | Worktree | Branch | Msgs | Updated |', '|---|---|---|---|---|---|---|---|---|', ...S.inventory.threads.sort((a, b) => (b.updated ?? 0) - (a.updated ?? 0)).map((t) => `| ${short(t.id)} | ${mdEscape(t.title ?? '')} | ${mdEscape(t.project)} | ${t.where} | ${t.mode ?? '?'} | ${t.worktree ? `\`${mdEscape(t.worktree)}\`` : '—'} | ${mdEscape(t.branch ?? '—')} | ${t.messages} | ${iso(t.updated)} |`)]);
  if (S.grants?.length) det(`Folder approvals (${S.grants.length})`, ['| Project | Path | Approved | Matches now | Notes |', '|---|---|---|---|---|', ...S.grants.map((r) => `| ${mdEscape(r.project)} | \`${mdEscape(r.grant.path)}\` | ${iso(r.grant.approvedAt)} | ${r.matches ? 'yes' : '**no**'} | ${mdEscape(r.problems.join('; ') || '—')} |`)]);
  if (S.inventory.worktrees?.length) det(`Worktrees (${S.inventory.worktrees.length})`, ['| Path | Chat | Project | Owner | Git | Size |', '|---|---|---|---|---|---|', ...S.inventory.worktrees.map((w) => `| \`${mdEscape(w.path)}\` | ${short(w.thread)} | \`${mdEscape(w.project ?? '—')}\` | ${w.owner ?? '—'} | ${w.git} | ${w.size ?? '—'} |`)]);
  if (S.inventory.journals?.length) det(`Transfer journals (${S.inventory.journals.length})`, S.inventory.journals.map((j) => `- ${j.dir}/${j.file} — ${j.chat ? `chat ${j.chat}` : 'unmatched'} — ${ago(j.age)}`));
  if (S.inventory.disks?.length) det('Disks', ['| What | Volume | Type | FS | Free |', '|---|---|---|---|---|', ...S.inventory.disks.map((d) => `| ${mdEscape(d.what)} | ${d.volume ?? '—'} | ${d.type ?? '—'} | ${d.fs ?? d.fsType ?? '—'} | ${fmtBytes(d.free)} |`)]);
  if (S.inventory.network?.length) det('Network', S.inventory.network.map((n) => `- ${n.what}: ${n.url} → ${n.status ?? n.error}${n.ms ? ` (${n.ms} ms)` : ''}`));
  if (S.inventory.profileFiles) det('Profile files', S.inventory.profileFiles.map((f) => `- ${f.name} — ${fmtBytes(f.size)} — ${iso(f.modified)}`));
  if (S.inventory.log) det('Log (last 60 lines)', [`\`${S.inventory.log.path}\` — ${fmtBytes(S.inventory.log.size)}, ${ago(S.inventory.log.modified)}`, '', '```text', ...(S.inventory.log.header ?? []), '…', S.logTail ?? '', '```']);
  det('Check timings', Object.entries(S.timings).map(([k, v]) => `- ${k}: ${v} ms`));

  L.push('## About this report', '');
  L.push('- The scan is read-only. Repairs run only with your consent, only while Freebuff is closed, while holding Freebuff\'s own profile lock, and back up every file they change.');
  L.push('- The repair tool sees only this computer. It cannot see the Cloud side of a chat (which folder fingerprint a chat expects), so a few causes can only be confirmed by Freebuff support.');
  L.push(`- Network: ${opts.offline ? 'none (--offline)' : 'unauthenticated GET requests to the Freebuff website, API home page and update feed only'}.`);
  L.push('');
  return redactor(P, opts)(L.join('\n'));
}

function printSummary(S) {
  const sorted = [...S.findings].sort((a, b) => SEVERITY[a.severity] - SEVERITY[b.severity]).filter((f) => f.severity !== 'ok');
  console.log('');
  for (const f of sorted.slice(0, 40)) console.log(`${TAG[f.severity]} ${f.area}: ${f.title}`);
  if (sorted.length > 40) console.log(`… ${sorted.length - 40} more in the report`);
  console.log(`\n${S.count('error')} error(s), ${S.count('warn')} warning(s), ${S.count('info')} note(s), ${S.count('ok')} passed — ${S.fixes.length} automatic repair(s) available.`);
}

async function main() {
  const compiled = !/^bun(-baseline)?(\.exe)?$/i.test(basename(process.execPath)) || /\$bunfs|~BUN/.test(import.meta.path ?? '');
  const argv = process.argv.slice(2);
  const opts = parseArgs(compiled && argv.length === 0 ? ['--ui'] : argv);
  const P = discoverPaths(opts);
  if (opts.restore) {
    const expanded = opts.restore.trim().replace(/^['"]|['"]$/g, '').replace(/^(~|%USERPROFILE%|\$env:USERPROFILE|\$HOME)(?=[\\/]|$)/i, P.home);
    restoreBackup(resolve(expanded), P); return 0;
  }
  if (!process.versions.bun) die('Run this with Bun (the launchers use the Bun inside Freebuff).');
  if (opts.ui) return runUi(opts, P);
  console.log(`Freebuff Repair Tool ${DOCTOR_VERSION} — scanning ${P.statePath} …`);
  const bar = termProgress();
  let S = await scan(opts, P, (p) => bar.update(p.done / p.total, `Checking ${p.step}…`, 'Scanning'));
  bar.stop();
  printSummary(S);
  const interactive = process.stdin.isTTY && process.stdout.isTTY;
  let fixResult = null, verify = null;
  if (S.fixes.length && (opts.fix || interactive)) {
    let proceed = opts.fix;
    if (!proceed) {
      console.log('\nAvailable repairs:'); for (const f of S.fixes) console.log(`  • ${f.title}`);
      proceed = await ask(S.appRunning ? '\nFreebuff is running; quit it first. Try the repairs anyway (they will be refused while it runs)?' : '\nReview and apply these repairs now? (each one is confirmed separately)');
    }
    if (proceed) {
      fixResult = await runFixes(S, P, opts);
      if (fixResult.blocked) console.log(`\n${fixResult.blocked}`);
      if (fixResult.applied.length) { const vb = termProgress(); verify = await scan({ ...opts, errors: [] }, P, (p) => vb.update(p.done / p.total, `Re-checking ${p.step}…`, 'Verifying')); vb.stop(); }
    }
  }
  const file = writeReport(S, P, opts, fixResult, verify);
  console.log(`\nReport written to: ${file}`);
  if (IS_WIN && interactive && opts.open) { try { spawn('notepad.exe', [file], { detached: true, stdio: 'ignore' }).unref(); } catch {} }
  const final = verify ?? S;
  return final.count('error') ? 1 : 0;
}

function writeReport(S, P, opts, fixResult, verify) {
  const outDir = resolve(opts.out ?? process.cwd());
  mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const file = join(outDir, `frt-report-${stamp}.md`);
  writeFileSync(file, renderReport(S, P, opts, fixResult, verify));
  if (opts.json) {
    const plain = S.findings.map(({ fix, ...f }) => ({ ...f, fix: fix ? { id: fix.id, title: fix.title, risk: fix.risk } : undefined }));
    writeFileSync(file.replace(/\.md$/, '.json'), redactor(P, opts)(JSON.stringify({ doctor: DOCTOR_VERSION, findings: plain, inventory: S.inventory, fixes: fixResult && { applied: fixResult.applied.map((a) => a.fix.id), failed: fixResult.failed.map((a) => ({ id: a.fix.id, error: a.error })), backupDir: fixResult.backupDir } }, null, 2)));
  }
  return file;
}

function openExternal(target, reveal = false) {
  try {
    if (IS_WIN) spawn(reveal ? 'explorer.exe' : 'rundll32.exe', reveal ? [`/select,${target}`] : ['url.dll,FileProtocolHandler', target], { detached: true, stdio: 'ignore', windowsHide: false }).unref();
    else if (IS_MAC) spawn('open', reveal ? ['-R', target] : [target], { detached: true, stdio: 'ignore' }).unref();
    else spawn('xdg-open', [reveal ? dirname(target) : target], { detached: true, stdio: 'ignore' }).unref();
    return true;
  } catch { return false; }
}

async function runUi(opts, P) {
  const token = randomUUID();
  const st = { phase: 'idle', progress: 0, step: '', install: null, counts: null, problems: [], fixes: [], report: null, reportText: '', fixSummary: null, error: null };
  let S = null, lastSeen = Date.now();
  const summarize = (X) => ({ error: X.count('error'), warn: X.count('warn'), info: X.count('info'), ok: X.count('ok') });
  const problems = (X) => [...X.findings].filter((f) => f.severity === 'error' || f.severity === 'warn').sort((a, b) => SEVERITY[a.severity] - SEVERITY[b.severity]).map((f) => ({ sev: f.severity, area: f.area, title: f.title, step: f.steps?.[0] ?? '', fixable: !!f.fix }));
  const redact = redactor(P, opts);
  const finish = (fixResult, verify) => {
    st.report = writeReport(S, P, opts, fixResult, verify);
    st.reportText = readFileSync(st.report, 'utf8');
    st.reportShown = redact(st.report);
  };
  async function doScan() {
    Object.assign(st, { phase: 'scanning', progress: 0, error: null, fixSummary: null });
    const bar = termProgress();
    try {
      S = await scan({ ...opts, errors: opts.errors }, P, (p) => { st.progress = p.done / p.total; st.step = p.step; bar.update(st.progress, `Checking ${p.step}…`, 'Scanning'); });
      bar.stop(`Scan finished: ${S.count('error')} error(s), ${S.count('warn')} warning(s), ${S.fixes.length} repair(s) available. See the browser window.`);
      st.progress = 1; st.install = S.install ? `Freebuff ${S.install.version ?? '?'} — ${redact(S.install.dir)}` : 'Freebuff installation not found';
      st.counts = summarize(S); st.problems = problems(S).map((x) => ({ ...x, title: redact(x.title), step: redact(x.step) }));
      st.fixes = S.fixes.map((f) => ({ title: redact(f.title), risk: f.risk }));
      st.appRunning = S.appRunning;
      finish(null, null);
      st.phase = S.fixes.length ? 'offer' : 'done';
    } catch (e) { st.error = e.message; st.phase = 'done'; }
  }
  async function doFix() {
    st.phase = 'fixing'; st.progress = 0; st.step = 'applying repairs';
    const bar = termProgress(); bar.update(0.1, 'Applying repairs…', 'Repairing');
    try {
      const r = await runFixes(S, P, { ...opts, yes: true, yesAll: true });
      let verify = null;
      if (r.applied.length) verify = await scan({ ...opts, errors: [] }, P, (p) => { st.progress = 0.3 + 0.7 * (p.done / p.total); st.step = `re-checking: ${p.step}`; bar.update(st.progress, `Re-checking ${p.step}…`, 'Verifying'); });
      bar.stop(`Repairs: ${r.applied.length} applied, ${r.failed.length} failed${r.blocked ? ' (blocked: Freebuff is running)' : ''}${verify ? `; ${verify.count('error')} error(s) left` : ''}.`);
      st.fixSummary = { blocked: r.blocked ? redact(r.blocked) : null, applied: r.applied.map((a) => redact(a.fix.title)), failed: r.failed.map((a) => `${redact(a.fix.title)} — ${redact(a.error)}`), skipped: r.skipped.map((a) => `${redact(a.fix.title)} — ${a.why}`), backup: r.backupDir ? redact(r.backupDir) : null, remaining: verify ? summarize(verify) : null };
      if (verify) st.counts = summarize(verify);
      if (verify) st.problems = problems(verify).map((x) => ({ ...x, title: redact(x.title), step: redact(x.step) }));
      finish(r, verify);
    } catch (e) { st.error = e.message; }
    st.progress = 1; st.phase = 'done';
  }
  const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  const server = Bun.serve({
    hostname: '127.0.0.1', port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.searchParams.get('t') !== token) return new Response('Forbidden', { status: 403 });
      lastSeen = Date.now();
      if (url.pathname === '/') return new Response(UI_HTML.replace('__TOKEN__', token).replace('__STATE__', () => JSON.stringify(st).replace(/</g, '\\u003c')), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
      if (url.pathname === '/api/state') return json(st);
      if (req.method !== 'POST') return new Response('Not found', { status: 404 });
      if (url.pathname === '/api/scan' && ['idle', 'done', 'offer'].includes(st.phase)) { doScan(); return json({ ok: true }); }
      if (url.pathname === '/api/fix' && st.phase === 'offer') { doFix(); return json({ ok: true }); }
      if (url.pathname === '/api/skip' && st.phase === 'offer') { st.phase = 'done'; return json({ ok: true }); }
      if (url.pathname === '/api/reveal' && st.report) return json({ ok: openExternal(st.report, true) });
      if (url.pathname === '/api/open' && st.report) return json({ ok: openExternal(st.report) });
      if (url.pathname === '/api/quit') { setTimeout(() => process.exit(0), 100); return json({ ok: true }); }
      return json({ ok: false }, 409);
    },
  });
  const link = `http://127.0.0.1:${server.port}/?t=${token}`;
  console.log(`Freebuff Repair Tool is open in your browser.\nIf it did not open, paste this address into your browser:\n  ${link}\n\nClose this window (or click "Close" on the page) when you are done.`);
  if (opts.open !== false) openExternal(link);
  await new Promise(() => setInterval(() => { if (Date.now() - lastSeen > 10 * 60 * 1000 && !['scanning', 'fixing'].includes(st.phase)) process.exit(0); }, 15000));
}

const UI_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Freebuff Repair Tool</title><style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--mut:#5b6470;--line:#e2e5ea;--acc:#3b6cf6;--err:#d23b3b;--warn:#c98a00;--ok:#1f9d55;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--card:#1b1e23;--fg:#e8eaed;--mut:#9aa3ad;--line:#2c3138;--acc:#6b8cff;--err:#ff6b6b;--warn:#f0b429;--ok:#3ecf8e;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px 16px}
main{max-width:760px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px}
button{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--fg);padding:9px 16px;border-radius:8px;cursor:pointer}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:600}button:disabled{opacity:.5;cursor:default}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.bar{height:10px;background:var(--line);border-radius:6px;overflow:hidden;margin:12px 0 6px}
.bar>i{display:block;height:100%;width:0;background:var(--acc);transition:width .3s}.mut{color:var(--mut);font-size:13px}
.counts{display:flex;gap:18px;flex-wrap:wrap;margin:6px 0 12px}.counts b{font-size:20px;display:block}
.e{color:var(--err)}.w{color:var(--warn)}.o{color:var(--ok)}ul{padding-left:20px;margin:8px 0}li{margin:6px 0}
textarea{width:100%;height:220px;font:12px/1.4 ui-monospace,Consolas,monospace;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px}
[hidden]{display:none!important}.note{padding:10px 12px;border-radius:8px;background:var(--bg);margin:10px 0}
</style></head><body><main>
<h1>Freebuff Repair Tool</h1><p class="sub">Finds and fixes problems with Freebuff: installation, sign-in, projects, chats, worktrees, missing buttons, themes and display glitches.</p>
<section class="card" id="start"><p>One click checks everything. It only reads files until you choose to repair.</p><button class="primary" id="go">Start scan</button></section>
<section class="card" id="prog" hidden><b id="phase">Scanning…</b><div class="bar"><i id="fill"></i></div><div class="mut" id="step"></div></section>
<section class="card" id="result" hidden>
 <div class="mut" id="install"></div>
 <div class="counts"><span><b class="e" id="ce">0</b>errors</span><span><b class="w" id="cw">0</b>warnings</span><span><b id="ci">0</b>notes</span><span><b class="o" id="co">0</b>passed</span></div>
 <div id="noproblems" class="o" hidden>No problems found.</div>
 <ul id="problems"></ul>
</section>
<section class="card" id="offer" hidden><b>Automatic repairs available</b>
 <div class="note" id="running" hidden>⚠️ Freebuff is open. Quit it completely (also from the tray / menu bar), then click Scan again before repairing.</div>
 <ul id="fixes"></ul><p class="mut">Every file is backed up first and repairs can be undone.</p>
 <div class="row"><button class="primary" id="fix">Repair automatically</button><button id="skip">Not now</button></div></section>
<section class="card" id="fixres" hidden><b id="fixtitle">Repair results</b><ul id="fixlist"></ul><div class="mut" id="backup"></div></section>
<section class="card" id="done" hidden><b>Report</b><p class="mut" id="path"></p>
 <div class="row"><button class="primary" id="copy">Copy report</button><button id="reveal">Show in folder</button><button id="openr">Open report</button><button id="again">Scan again</button><button id="quit">Close</button></div>
 <p class="mut" id="copied"></p><textarea id="text" readonly></textarea></section>
<p class="mut" id="err"></p>
</main><script>
const T='__TOKEN__',$=id=>document.getElementById(id);
const post=p=>fetch(p+'?t='+T,{method:'POST'}).then(r=>r.json()).catch(()=>({}));
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let timer=null;
function show(st){
 const busy=st.phase==='scanning'||st.phase==='fixing';
 $('start').hidden=st.phase!=='idle';$('prog').hidden=!busy;
 $('phase').textContent=st.phase==='fixing'?'Repairing…':'Scanning…';$('fill').style.width=Math.round(st.progress*100)+'%';$('step').textContent=st.step?('Checking '+st.step+'…'):'';
 const have=!!st.counts;$('result').hidden=!have||busy;
 if(have){$('install').textContent=st.install||'';$('ce').textContent=st.counts.error;$('cw').textContent=st.counts.warn;$('ci').textContent=st.counts.info;$('co').textContent=st.counts.ok;
  $('noproblems').hidden=st.problems.length>0;
  $('problems').innerHTML=st.problems.slice(0,25).map(p=>'<li><span class="'+(p.sev==='error'?'e':'w')+'">'+(p.sev==='error'?'●':'▲')+'</span> <b>'+esc(p.title)+'</b>'+(p.step?'<br><span class="mut">'+esc(p.step)+'</span>':'')+'</li>').join('')+(st.problems.length>25?'<li class="mut">…and '+(st.problems.length-25)+' more in the report</li>':'');}
 $('offer').hidden=st.phase!=='offer';$('running').hidden=!st.appRunning;$('fix').disabled=!!st.appRunning;
 $('fixes').innerHTML=st.fixes.map(f=>'<li>'+esc(f.title)+'<br><span class="mut">Risk: '+esc(f.risk)+'</span></li>').join('');
 const fr=st.fixSummary;$('fixres').hidden=!fr||busy;
 if(fr){const ok=fr.applied.length&&!fr.failed.length&&(!fr.remaining||!fr.remaining.error);
  $('fixtitle').innerHTML=fr.blocked?'<span class="w">Repairs not applied</span>':ok?'<span class="o">✔ Repairs worked</span>':'<span class="w">Some problems remain</span>';
  $('fixlist').innerHTML=(fr.blocked?'<li>'+esc(fr.blocked)+'</li>':'')+fr.applied.map(x=>'<li class="o">✔ '+esc(x)+'</li>').join('')+fr.failed.map(x=>'<li class="e">✖ '+esc(x)+'</li>').join('')+fr.skipped.map(x=>'<li class="mut">○ '+esc(x)+'</li>').join('')+(fr.remaining?'<li>After repair: '+fr.remaining.error+' error(s), '+fr.remaining.warn+' warning(s) left</li>':'');
  $('backup').textContent=fr.backup?'Backups: '+fr.backup:'';}
 $('done').hidden=st.phase!=='done'||!st.reportText;
 if(st.reportText&&$('text').value!==st.reportText){$('text').value=st.reportText;$('path').textContent=st.reportShown||'';}
 $('err').textContent=st.error?'Error: '+st.error:'';
 if(busy&&!timer)timer=setInterval(poll,400);if(!busy&&timer){clearInterval(timer);timer=null;}
}
let phase=null;const INIT=__STATE__;phase=INIT.phase;show(INIT);const poll=()=>fetch('/api/state?t='+T).then(r=>r.json()).then(s=>{phase=s.phase;show(s)}).catch(()=>{});
$('go').onclick=$('again').onclick=()=>post('/api/scan').then(poll).then(()=>{if(!timer)timer=setInterval(poll,400)});
$('fix').onclick=()=>post('/api/fix').then(()=>{if(!timer)timer=setInterval(poll,400)});
$('skip').onclick=()=>post('/api/skip').then(poll);
$('reveal').onclick=()=>post('/api/reveal');$('openr').onclick=()=>post('/api/open');
$('quit').onclick=()=>post('/api/quit').then(()=>{document.body.innerHTML='<main><h1>Freebuff Repair Tool closed</h1><p class="sub">You can close this tab.</p></main>'});
$('copy').onclick=async()=>{const t=$('text').value;try{await navigator.clipboard.writeText(t)}catch{$('text').select();document.execCommand('copy')}$('copied').textContent='Copied — paste it into your support message.';};
setInterval(()=>fetch('/api/state?t='+T).catch(()=>{}),30000);
poll().then(()=>{ if(phase==='idle'&&new URLSearchParams(location.search).get('auto')!=='0') $('go').click(); });
</script></body></html>`;

main().then((code) => process.exit(code), (e) => { console.error(`Freebuff Repair Tool failed: ${e?.stack ?? e}`); process.exit(2); });
