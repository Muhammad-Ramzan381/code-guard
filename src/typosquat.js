const POPULAR = [
  'axios', 'babel', 'chalk', 'commander', 'cors', 'debug', 'dotenv', 'eslint', 'express', 'glob',
  'jest', 'jquery', 'lodash', 'minimist', 'moment', 'mongoose', 'next', 'nodemon', 'prettier',
  'react', 'react-dom', 'redux', 'request', 'rimraf', 'semver', 'typescript', 'uuid', 'vite',
  'vue', 'webpack', 'yargs',
];
const POPULAR_SET = new Set(POPULAR);

/** Optimal string alignment distance, so a swapped pair like "lodahs" counts as one typo. */
export function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[a.length][b.length];
}

export function checkTyposquat(pkg) {
  const name = pkg.name;
  if (POPULAR_SET.has(name) || name.length < 4 || name.startsWith('@')) return null;
  const target = POPULAR.find((p) => p.length >= 4 && editDistance(name, p) === 1);
  if (!target) return null;
  return {
    id: 'possible-typosquat',
    kind: 'suspicious-name',
    severity: 'medium',
    package: name,
    version: pkg.version,
    location: pkg.location,
    title: `Name is one typo away from "${target}"`,
  };
}
