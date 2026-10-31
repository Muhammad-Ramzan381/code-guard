import { afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFixture } from '../scripts/fixture.js';
import { runScan } from '../src/scan.js';
import { scanPackage } from '../src/heuristics.js';
import { lookupAdvisories } from '../src/osv.js';
import { appendAuditEntry, findChainBreak, readAuditLog, canonicalize, sha256 } from '../src/report.js';
import { explainFindings } from '../src/gemma.js';
import { MEMO_PROGRAM_ID, verifyAttestation } from '../src/solana.js';
import { Keypair } from '@solana/web3.js';

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
const temp = () => mkdtempSync(join(tmpdir(), 'codeguard-hardening-'));

test('offline scan makes no requests, finds the nested fixture, and remains incomplete', async () => {
  globalThis.fetch = () => assert.fail('Offline scan used the network');
  const { report } = await runScan(createFixture(temp()), { offline: true, apiKey: 'must-not-be-used' });
  assert.equal(report.maxDepth, 2);
  assert.equal(report.sourceScanned, 2);
  assert.equal(report.incomplete, true);
  assert.ok(report.findings.some((f) => f.id === 'credential-exfiltration'));
  assert.ok(report.findings.some((f) => f.id === 'possible-typosquat'));
});

test('untrusted lockfile paths cannot escape the scan root', () => {
  assert.throws(() => scanPackage(temp(), { location: '../outside/node_modules/x' }), /leaves/);
});

test('oversized files make source coverage incomplete', () => {
  const root = temp();
  mkdirSync(join(root, 'node_modules/x'), { recursive: true });
  writeFileSync(join(root, 'node_modules/x/big.js'), ' '.repeat(1024 * 1024 + 1));
  assert.equal(scanPackage(root, { name: 'x', location: 'node_modules/x' }).scanned, false);
});

test('a malformed OSV batch is an error, never a clean lookup', async () => {
  globalThis.fetch = async () => new Response(JSON.stringify({ results: [] }));
  await assert.rejects(lookupAdvisories([{ name: 'x', version: '1' }]), /incomplete batch/);
});

test('sequence numbers are validated even if an entry is rehashed', () => {
  const body = { seq: 9, prevHash: null, reportHash: 'example' };
  assert.equal(findChainBreak([{ ...body, entryHash: sha256(canonicalize(body)) }]), 1);
});

test('an altered audit log cannot be extended', () => {
  const file = join(temp(), 'audit.jsonl');
  appendAuditEntry(file, { reportHash: 'one' });
  const entries = readAuditLog(file);
  entries[0].reportHash = 'changed';
  writeFileSync(file, JSON.stringify(entries[0]) + '\n');
  assert.throws(() => appendAuditEntry(file, { reportHash: 'two' }), /altered/);
});

test('model overrides are read after env loading and API errors do not expose response bodies', async () => {
  const original = process.env.GEMMA_MODEL;
  try {
    process.env.GEMMA_MODEL = 'gemma-4-31b-it';
    globalThis.fetch = async (url) => {
      assert.match(url, /gemma-4-31b-it:generateContent$/);
      return new Response('secret-response-content', { status: 403 });
    };
    const warnings = await explainFindings([{ package: 'x', title: 'suspect' }], { apiKey: 'key' });
    assert.match(warnings[0], /403/);
    assert.ok(!warnings[0].includes('secret-response-content'));
  } finally {
    if (original === undefined) delete process.env.GEMMA_MODEL;
    else process.env.GEMMA_MODEL = original;
  }
});

test('onchain verification rejects wrong memos, failed transactions, and missing signers', async () => {
  const signer = Keypair.generate().publicKey;
  const tx = { meta: { err: null }, slot: 42, transaction: { message: {
    instructions: [{ programId: MEMO_PROGRAM_ID, parsed: 'memo' }],
    accountKeys: [{ pubkey: signer, signer: true }],
  } } };
  const connection = { getParsedTransaction: async () => tx };
  const expected = { memo: 'memo', signer: signer.toBase58() };
  assert.equal((await verifyAttestation(connection, 'sig', expected)).ok, true);
  assert.equal((await verifyAttestation(connection, 'sig', { ...expected, memo: 'wrong' })).ok, false);
  tx.transaction.message.accountKeys[0].signer = false;
  assert.equal((await verifyAttestation(connection, 'sig', expected)).ok, false);
  tx.meta.err = { error: true };
  assert.equal((await verifyAttestation(connection, 'sig', expected)).ok, false);
});
