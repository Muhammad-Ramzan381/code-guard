import { readLockfile } from './lockfile.js';
import { lookupAdvisories } from './osv.js';
import { scanPackage } from './heuristics.js';
import { checkTyposquat } from './typosquat.js';
import { explainFindings } from './gemma.js';
import { countBySeverity, sortFindings } from './report.js';

/** Runs every check. `incomplete` is true whenever a check could not run, so "clean" is never overclaimed. */
export async function runScan(projectDir, { apiKey, explainLimit, offline = false } = {}) {
  const packages = readLockfile(projectDir);
  const warnings = [];
  const findings = [];

  let advisories = [];
  let advisoryLookup = 'ok';
  try {
    if (offline) throw new Error('offline mode requested');
    const result = await lookupAdvisories(packages);
    findings.push(...result.findings);
    advisories = result.advisories;
  } catch (err) {
    advisoryLookup = 'failed';
    warnings.push(`OSV lookup failed, known advisories were NOT checked: ${err.message}`);
  }

  let sourceScanned = 0;
  for (const pkg of packages) {
    try {
      const { scanned, findings: found } = scanPackage(projectDir, pkg);
      if (scanned) sourceScanned++;
      findings.push(...found);
    } catch (err) {
      warnings.push(`Source scan failed for ${pkg.location}: ${err.message}`);
    }
    const squat = checkTyposquat(pkg);
    if (squat) findings.push(squat);
  }
  if (sourceScanned < packages.length) {
    warnings.push(`Source coverage incomplete for ${packages.length - sourceScanned} of ${packages.length} packages (missing, unreadable, symlinked, or oversized files). For missing dependencies use npm ci --ignore-scripts.`);
  }

  const sorted = sortFindings(findings);
  warnings.push(...(await explainFindings(sorted, { apiKey: offline ? undefined : apiKey, limit: explainLimit })));

  return {
    report: {
      tool: 'codeguard',
      schema: 1,
      scannedAt: new Date().toISOString(),
      packageCount: packages.length,
      maxDepth: Math.max(0, ...packages.map((p) => p.depth)),
      sourceScanned,
      advisoryLookup,
      incomplete: advisoryLookup !== 'ok' || sourceScanned < packages.length,
      counts: countBySeverity(sorted),
      findings: sorted,
      warnings,
    },
    packages,
    advisories,
  };
}
