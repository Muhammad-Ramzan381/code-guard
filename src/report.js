import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const ORDER = ['critical', 'high', 'medium', 'low'];

export function sortFindings(findings) {
  return [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
}

export function countBySeverity(findings) {
  const counts = Object.fromEntries(ORDER.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** JSON with sorted keys, so the same report always hashes the same. */
export function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    const body = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`);
    return `{${body.join(',')}}`;
  }
  return JSON.stringify(value);
}

export const sha256 = (text) => createHash('sha256').update(text).digest('hex');
export const hashReport = (report) => sha256(canonicalize(report));

export function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function readAuditLog(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

export function appendAuditEntry(path, fields) {
  const log = readAuditLog(path);
  const prevHash = log.at(-1)?.entryHash ?? null;
  if (findChainBreak(log) !== null) throw new Error('Refusing to append to an altered audit log');
  const body = { ...fields, seq: log.length + 1, prevHash };
  const entry = { ...body, entryHash: sha256(canonicalize(body)) };
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, `${JSON.stringify(entry)}\n`);
  return entry;
}

/** Returns the seq of the first tampered entry, or null when the chain is intact. */
export function findChainBreak(entries) {
  let prevHash = null;
  for (const [index, entry] of entries.entries()) {
    const { entryHash, ...body } = entry;
    if (entry.seq !== index + 1 || entry.prevHash !== prevHash || sha256(canonicalize(body)) !== entryHash) return index + 1;
    prevHash = entryHash;
  }
  return null;
}

const csvCell = (v) => `"${String(v ?? '').replaceAll('"', '""')}"`;

export function toCsv(columns, rows) {
  return [columns.join(','), ...rows.map((r) => columns.map((c) => csvCell(r[c])).join(','))].join('\n') + '\n';
}
