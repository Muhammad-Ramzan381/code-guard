const OSV = 'https://api.osv.dev/v1';
const BATCH_SIZE = 500;
const DETAIL_CONCURRENCY = 8;

const SEVERITY = { LOW: 'low', MODERATE: 'medium', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical' };

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`OSV ${res.status} ${res.statusText}`);
  return res.json();
}

async function queryIds(pkg) {
  const ids = [];
  let pageToken;
  do {
    const data = await postJson(`${OSV}/query`, {
      package: { ecosystem: 'npm', name: pkg.name },
      version: pkg.version,
      ...(pageToken ? { page_token: pageToken } : {}),
    });
    ids.push(...(data.vulns ?? []).map((v) => v.id));
    pageToken = data.next_page_token;
  } while (pageToken);
  return ids;
}

/** Returns one vulnerability id list per input package, following OSV pagination. */
async function batchIds(pkgs) {
  const results = [];
  for (let i = 0; i < pkgs.length; i += BATCH_SIZE) {
    const chunk = pkgs.slice(i, i + BATCH_SIZE);
    const data = await postJson(`${OSV}/querybatch`, {
      queries: chunk.map((p) => ({ package: { ecosystem: 'npm', name: p.name }, version: p.version })),
    });
    if (!Array.isArray(data.results) || data.results.length !== chunk.length) throw new Error('OSV returned an incomplete batch');
    for (const [j, row] of data.results.entries()) {
      // A next_page_token means this package has more results than the batch returned.
      results.push(row.next_page_token ? await queryIds(chunk[j]) : (row.vulns ?? []).map((v) => v.id));
    }
  }
  return results;
}

async function fetchDetails(ids) {
  const details = new Map();
  const queue = [...ids];
  await Promise.all(
    Array.from({ length: DETAIL_CONCURRENCY }, async () => {
      while (queue.length) {
        const id = queue.pop();
        const res = await fetch(`${OSV}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(20000) });
        if (!res.ok) throw new Error(`OSV ${res.status} for ${id}`);
        details.set(id, await res.json());
      }
    }),
  );
  return details;
}

export function severityOf(vuln) {
  if (vuln.id.startsWith('MAL-')) return 'critical';
  return SEVERITY[String(vuln.database_specific?.severity).toUpperCase()] ?? 'medium';
}

/** Looks up known advisories. Network failures propagate so a failed lookup is never read as clean. */
export async function lookupAdvisories(packages) {
  const seen = new Map();
  for (const p of packages) seen.set(`${p.name}@${p.version}`, p);
  const unique = [...seen.values()];

  const idLists = await batchIds(unique);
  const details = await fetchDetails(new Set(idLists.flat()));

  const byKey = new Map(unique.map((p, i) => [`${p.name}@${p.version}`, idLists[i]]));
  const findings = [];
  for (const p of packages) {
    for (const id of byKey.get(`${p.name}@${p.version}`)) {
      const vuln = details.get(id);
      findings.push({
        kind: id.startsWith('MAL-') ? 'known-malicious' : 'known-vulnerability',
        id,
        severity: severityOf(vuln),
        package: p.name,
        version: p.version,
        location: p.location,
        title: vuln.summary ?? id,
        detail: (vuln.details ?? '').slice(0, 2000),
        // Advisory ranges may contain multiple release branches; do not recommend
        // the first fixed event as though it fixes this installed version.
        fixedIn: null,
        reference: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
      });
    }
  }
  return { findings, advisories: [...details.values()] };
}
