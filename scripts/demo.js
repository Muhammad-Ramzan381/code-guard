import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createFixture } from './fixture.js';

const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const target = createFixture(resolve('.codeguard/demo'));
console.log('Code Guard: offline training demo (inert fixtures, no API calls)');
const scan = spawnSync(process.execPath, [cli, 'scan', target, '--offline', '--attest', 'simulate'], { stdio: 'inherit' });
if (scan.status !== 2) throw new Error('Offline scan should return incomplete status 2');
const report = JSON.parse(readFileSync(join('.codeguard', 'report.json'), 'utf8'));
if (!report.findings.some((f) => f.id === 'credential-exfiltration') || report.maxDepth !== 2) throw new Error('Expected nested suspicious dependency finding');
const verify = spawnSync(process.execPath, [cli, 'verify'], { stdio: 'inherit' });
if (verify.status !== 2) throw new Error('Simulated verification must return not-onchain status 2');
console.log('\nDemo passed. Reports and Snowflake CSV exports are in .codeguard/.');
