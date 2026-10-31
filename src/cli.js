#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { runScan } from './scan.js';
import { appendAuditEntry, findChainBreak, hashReport, readAuditLog, toCsv, writeJson } from './report.js';
import { severityOf } from './osv.js';

if (existsSync('.env')) process.loadEnvFile('.env');

const STATE = '.codeguard';
const PATHS = {
  report: join(STATE, 'report.json'),
  audit: join(STATE, 'audit-log.jsonl'),
  wallet: join(STATE, 'wallet.json'),
  agent: join(STATE, 'agent.json'),
  csv: join(STATE, 'snowflake'),
};

const USAGE = `codeguard: audit an npm project's full dependency tree

  codeguard scan <dir> [--offline] [--attest none|simulate|devnet] [--explain N]
  codeguard wallet                 create or show the devnet wallet
  codeguard register [--uri URI]   register the agent on the Solana Agent Registry
  codeguard verify                 check the report against the audit log and devnet

Exit codes: 0 no critical/high findings, 1 critical/high found, 2 incomplete scan or error`;

function printReport(report) {
  const c = report.counts;
  console.log(`\nScanned ${report.packageCount} packages, up to ${report.maxDepth} levels deep`);
  console.log(`critical ${c.critical} | high ${c.high} | medium ${c.medium} | low ${c.low}\n`);
  for (const f of report.findings) {
    const where = f.file ? ` (${f.file}${f.line ? `:${f.line}` : ''})` : '';
    console.log(`[${f.severity.toUpperCase()}] ${f.package}@${f.version} ${f.id}${where}`);
    console.log(`  ${f.title}`);
    if (f.explanation) console.log(`  [${f.explainedBy}] ${f.explanation.replaceAll('\n', '\n  ')}`);
  }
  for (const w of report.warnings) console.log(`\nWARNING: ${w}`);
  if (report.incomplete) console.log('\nThis scan is INCOMPLETE: no findings here would not mean the project is clean.');
}

function exportCsv(report, packages, advisories) {
  mkdirSync(PATHS.csv, { recursive: true });
  const write = (name, columns, rows) => writeFileSync(join(PATHS.csv, name), toCsv(columns, rows));
  write('scan_packages.csv', ['name', 'version', 'location', 'depth', 'dev'], packages);
  write('scan_findings.csv', ['kind', 'id', 'severity', 'package', 'version', 'location', 'title'], report.findings);
  write(
    'osv_advisories.csv',
    ['id', 'severity', 'summary', 'published', 'modified'],
    advisories.map((a) => ({ ...a, severity: severityOf(a) })),
  );
}

async function attestDevnet(reportHash, counts) {
  const solana = await import('./solana.js');
  if (!existsSync(PATHS.agent)) throw new Error('Agent not registered. Run: codeguard register');
  const { asset } = JSON.parse(readFileSync(PATHS.agent, 'utf8'));
  const wallet = solana.loadWallet(PATHS.wallet);
  const memo = solana.formatMemo({ agentAsset: asset, reportHash, counts });
  const signature = await solana.attestReport(solana.connect(), wallet, memo);
  console.log(`\nAttested on devnet: ${solana.explorerUrl(signature)}`);
  return { mode: 'devnet', agentAsset: asset, signer: wallet.publicKey.toBase58(), memo, signature };
}

async function scan(target, values) {
  if (!['none', 'simulate', 'devnet'].includes(values.attest ?? 'none')) throw new Error('Invalid --attest value');
  const explainLimit = Number(values.explain ?? 5);
  if (!Number.isSafeInteger(explainLimit) || explainLimit < 0) throw new Error('--explain must be a nonnegative integer');
  const projectDir = resolve(target);
  const { report, packages, advisories } = await runScan(projectDir, {
    apiKey: values.offline ? undefined : process.env.GEMINI_API_KEY,
    explainLimit,
    offline: values.offline,
  });
  printReport(report);
  writeJson(PATHS.report, report);
  exportCsv(report, packages, advisories);

  const reportHash = hashReport(report);
  console.log(`\nReport: ${PATHS.report}\nSHA-256: ${reportHash}`);

  const attest = values.attest ?? 'none';
  if (attest === 'devnet' || attest === 'simulate') {
    // A simulated entry has no signature, so it can never be mistaken for an onchain record.
    const proof = attest === 'devnet' ? await attestDevnet(reportHash, report.counts) : { mode: 'simulated', signature: null };
    if (attest === 'simulate') console.log('\nSIMULATED attestation: written locally, nothing was sent to Solana.');
    appendAuditEntry(PATHS.audit, { reportHash, scannedAt: report.scannedAt, counts: report.counts, ...proof });
  } else if (attest !== 'none') {
    throw new Error(`Unknown --attest value: ${attest}`);
  }

  if (report.incomplete) return 2;
  return report.counts.critical + report.counts.high > 0 ? 1 : 0;
}

async function wallet() {
  const solana = await import('./solana.js');
  const { wallet: kp, created } = solana.ensureWallet(PATHS.wallet);
  const address = kp.publicKey.toBase58();
  console.log(`${created ? 'Created' : 'Existing'} devnet wallet: ${address}`);
  console.log(`Balance: ${await solana.balanceSol(solana.connect(), kp.publicKey)} SOL`);
  console.log('Fund it at https://faucet.solana.com (choose devnet). Test SOL has no real value.');
  return 0;
}

async function register(values) {
  if (existsSync(PATHS.agent)) throw new Error(`Already registered, see ${PATHS.agent}`);
  const solana = await import('./solana.js');
  const kp = solana.loadWallet(PATHS.wallet);
  const { asset, signature } = await solana.registerAgent(solana.connect(), kp, values.uri);
  writeJson(PATHS.agent, { asset, signature, owner: kp.publicKey.toBase58(), cluster: 'devnet' });
  console.log(`Registered agent ${asset}\n${solana.explorerUrl(signature)}`);
  return 0;
}

async function verify() {
  const entries = readAuditLog(PATHS.audit);
  if (!entries.length) throw new Error(`No audit entries in ${PATHS.audit}`);
  const broken = findChainBreak(entries);
  if (broken !== null) {
    console.log(`FAIL: audit log was altered at entry ${broken}`);
    return 1;
  }
  console.log(`Audit chain intact (${entries.length} entries)`);

  const latest = entries.at(-1);
  const currentHash = hashReport(JSON.parse(readFileSync(PATHS.report, 'utf8')));
  if (currentHash !== latest.reportHash) {
    console.log('FAIL: report.json does not match the latest audit entry');
    return 1;
  }
  console.log('Report matches the latest audit entry');

  if (latest.mode !== 'devnet') {
    console.log('NOT VERIFIED ONCHAIN: the latest entry is simulated.');
    return 2;
  }
  const solana = await import('./solana.js');
  if (latest.memo !== solana.formatMemo({ agentAsset: latest.agentAsset, reportHash: latest.reportHash, counts: latest.counts })) {
    console.log('FAIL: memo does not bind this agent, report hash, and counts');
    return 1;
  }
  const result = await solana.verifyAttestation(solana.connect(), latest.signature, latest);
  if (!result.ok) {
    console.log(`FAIL: ${result.reason}`);
    return 1;
  }
  console.log(`Verified onchain at slot ${result.slot}, signer ${latest.signer}`);
  console.log(solana.explorerUrl(latest.signature));
  return 0;
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: { attest: { type: 'string' }, explain: { type: 'string' }, uri: { type: 'string' }, offline: { type: 'boolean' }, help: { type: 'boolean', short: 'h' } },
  });
  const [command, target] = positionals;
  if (values.help || !command) { console.log(USAGE); return 0; }
  if (values.offline && (values.attest === 'devnet' || ['wallet', 'register'].includes(command))) throw new Error('--offline cannot be combined with devnet operations');
  if (command === 'scan' && target) return scan(target, values);
  if (command === 'wallet') return wallet();
  if (command === 'register') return register(values);
  if (command === 'verify') return verify();
  console.log(USAGE);
  return 2;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error(`Error: ${err.message}`);
    process.exitCode = 2;
  },
);
