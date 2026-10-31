import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const MARKER = 'node_modules/';

/** Reads package-lock.json and returns every installed package, however deep. */
export function readLockfile(projectDir) {
  const path = join(projectDir, 'package-lock.json');
  let lock;
  try {
    lock = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`Cannot read ${path}: ${err.message}`);
  }
  if (lock.packages) return fromPackages(lock.packages);
  if (lock.dependencies) return fromLegacy(lock.dependencies);
  throw new Error(`${path} has neither "packages" nor "dependencies"`);
}

function fromPackages(packages) {
  const out = [];
  for (const [location, entry] of Object.entries(packages)) {
    if (!location.includes(MARKER) || entry.link || !entry.version) continue;
    out.push({
      name: entry.name ?? location.slice(location.lastIndexOf(MARKER) + MARKER.length),
      version: entry.version,
      location,
      depth: location.split(MARKER).length - 1,
      dev: Boolean(entry.dev),
    });
  }
  return out;
}

function fromLegacy(dependencies, parent = '', depth = 1) {
  const out = [];
  for (const [name, entry] of Object.entries(dependencies)) {
    const location = `${parent}${MARKER}${name}`;
    if (entry.version) out.push({ name, version: entry.version, location, depth, dev: Boolean(entry.dev) });
    if (entry.dependencies) out.push(...fromLegacy(entry.dependencies, `${location}/`, depth + 1));
  }
  return out;
}
