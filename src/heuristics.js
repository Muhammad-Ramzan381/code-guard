import { existsSync, readdirSync, readFileSync, statSync, realpathSync } from 'node:fs';
import { extname, join, relative, resolve, isAbsolute } from 'node:path';

const MAX_FILE_BYTES = 1024 * 1024;
const SOURCE_EXT = new Set(['.js', '.cjs', '.mjs', '.ts']);
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];
const RISKY_HOOK = /curl|wget|powershell|\bnode\s+-e\b|base64|\|\s*(ba)?sh/i;

const RULES = [
  {
    id: 'decode-and-execute',
    severity: 'high',
    title: 'Decodes hidden data and executes it',
    pattern: /(eval|new\s+Function)\s*\(\s*(atob\s*\(|Buffer\.from\s*\([^)]*(base64|hex))/,
  },
  {
    id: 'env-harvest',
    severity: 'medium',
    title: 'Serializes the entire process environment',
    pattern: /(JSON\.stringify|Object\.(entries|keys|values))\s*\(\s*process\.env\s*\)/,
    signal: 'secrets',
  },
  {
    id: 'credential-file-read',
    severity: 'high',
    title: 'References a local credential file',
    pattern: /\.npmrc|\.ssh[/\\]+id_|\.aws[/\\]+credentials|\.git-credentials/,
    signal: 'secrets',
  },
  {
    id: 'remote-shell',
    severity: 'high',
    title: 'Pipes a remote download into a shell',
    pattern: /(curl|wget)\b[^|\n]*\|\s*(ba)?sh/,
  },
  {
    id: 'network-call',
    severity: 'info',
    title: 'Makes an outbound network call',
    pattern: /\b(https?\.(request|get)|fetch|axios\.(get|post))\s*\(/,
    signal: 'network',
  },
  {
    id: 'exfil-endpoint',
    severity: 'medium',
    title: 'Contacts a raw IP or webhook endpoint',
    pattern: /https?:\/\/(\d{1,3}\.){3}\d{1,3}|discord(app)?\.com\/api\/webhooks|webhook\.site/,
    signal: 'network',
  },
  {
    id: 'encoded-blob',
    severity: 'low',
    title: 'Contains a long encoded string',
    pattern: /["'`][A-Za-z0-9+/]{200,}={0,2}["'`]/,
  },
];

function sourceFiles(dir, coverage) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    // Nested node_modules are separate lockfile entries, and symlinks can leave the package.
    if (entry.name === 'node_modules') continue;
    if (entry.isSymbolicLink()) { coverage.skipped++; continue; }
    const full = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...sourceFiles(full, coverage));
    else if (SOURCE_EXT.has(extname(entry.name))) {
      if (statSync(full).size <= MAX_FILE_BYTES) files.push(full);
      else coverage.skipped++;
    }
  }
  return files;
}

function scanFile(text) {
  const hits = [];
  for (const [index, line] of text.split('\n').entries()) {
    for (const rule of RULES) {
      if (rule.pattern.test(line)) hits.push({ rule, line: index + 1, evidence: line.trim().slice(0, 160) });
    }
  }
  return hits;
}

const base = (pkg) => ({ package: pkg.name, version: pkg.version, location: pkg.location });

function installHookFindings(pkg, dir) {
  const manifestPath = join(dir, 'package.json');
  if (!existsSync(manifestPath)) return [];
  if (!inside(dir, realpathSync(manifestPath))) throw new Error('Manifest points outside the package');
  let scripts;
  try {
    scripts = JSON.parse(readFileSync(manifestPath, 'utf8')).scripts ?? {};
  } catch {
    throw new Error('Invalid package.json');
  }
  return INSTALL_HOOKS.filter((hook) => typeof scripts[hook] === 'string' && scripts[hook]).map((hook) => ({
    ...base(pkg),
    id: `install-hook:${hook}`,
    kind: 'suspicious-code',
    severity: RISKY_HOOK.test(scripts[hook]) ? 'high' : 'low',
    title: `Runs a ${hook} script when installed`,
    file: 'package.json',
    evidence: scripts[hook].slice(0, 160),
  }));
}

/** Scans one installed package without ever importing or executing its code. */
function inside(root, path) {
  const rel = relative(root, path);
  return rel !== '..' && !rel.startsWith('../') && !rel.startsWith('..\\') && !isAbsolute(rel);
}

export function scanPackage(projectDir, pkg) {
  const root = realpathSync(projectDir);
  const dir = resolve(root, pkg.location);
  if (!inside(root, dir) || dir === root) throw new Error('Package path leaves the project');
  if (!existsSync(dir)) return { scanned: false, findings: [] };
  if (!inside(root, realpathSync(dir))) throw new Error('Package symlink leaves the project');

  const findings = installHookFindings(pkg, dir);
  const coverage = { skipped: 0 };
  for (const file of sourceFiles(dir, coverage)) {
    const hits = scanFile(readFileSync(file, 'utf8'));
    const rel = relative(dir, file).replaceAll('\\', '/');
    const signals = new Set(hits.map((h) => h.rule.signal));
    for (const { rule, line, evidence } of hits) {
      if (rule.severity === 'info') continue;
      findings.push({
        ...base(pkg),
        id: rule.id,
        kind: 'suspicious-code',
        severity: rule.severity,
        title: rule.title,
        file: rel,
        line,
        evidence,
      });
    }
    // Neither signal is damning alone; together in one file they match credential theft.
    if (signals.has('secrets') && signals.has('network')) {
      findings.push({
        ...base(pkg),
        id: 'credential-exfiltration',
        kind: 'suspicious-code',
        severity: 'critical',
        title: 'Reads secrets and makes network calls in the same file',
        file: rel,
      });
    }
  }
  return { scanned: coverage.skipped === 0, findings };
}
