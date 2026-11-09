#!/usr/bin/env node
// Vendor-boundary eval. Dependency-free; Node 22 or later. Copy this file byte for byte to
// scripts/vendor-boundary.mjs in every Allowit repository.
//
//   node scripts/vendor-boundary.mjs              scan the repository that contains the cwd
//   node scripts/vendor-boundary.mjs --self-test  check the rules against in-memory cases
//   node scripts/vendor-boundary.mjs --probe      prove that an added vendor name fails the scan
//
// vendor-boundary.json at the repository root sets the role:
//   {"role":"shared"}                          no vendor term anywhere (empty baseline)
//   {"role":"shared","lockfiles":true}         same, and lockfiles are scanned too
//   {"role":"sdk"}                             vendor terms only on import or dependency lines
//                                              of the fixed registration files below
//   {"role":"vendor","vendors":["<name>"]}     only the named vendors' own terms
// Exit codes: 0 clean, 1 findings, 2 configuration or usage error.
// Terms are assembled from fragments so that this file does not match its own rules.
import {execFileSync} from 'node:child_process';
import {readFileSync, existsSync} from 'node:fs';
import {join, basename} from 'node:path';
import {pathToFileURL} from 'node:url';

const j = (...parts) => parts.join('');
// Vendor -> distinctive names (substring), sub-words (identifier tokens) and literal patterns.
const VENDORS = {
  [j('stel', 'lar')]: {
    names: [j('stel', 'lar'), j('soro', 'ban'), j('freigh', 'ter'), j('stro', 'op')],
    words: [j('hori', 'zon'), j('x', 'lm'), j('x', 'dr'), j('lu', 'men'), j('lu', 'mens'), j('str', 'key')],
    patterns: [
      new RegExp(j('\\bsep-?(?:10|41|56)\\b'), 'i'),
      new RegExp(j('\\b[GCM][A-Z2-7]', '{55}\\b')),
      new RegExp(j('\\bS[A-Z2-7]', '{55}\\b')),
      new RegExp(j('SD', 'F Network'), 'i'),
    ],
  },
  [j('sol', 'ana')]: {names: [j('sol', 'ana'), j('lam', 'port')], words: [j('phan', 'tom'), j('sp', 'l')], patterns: []},
  [j('tem', 'po')]: {names: [], words: [j('tem', 'po'), j('vi', 'em')], patterns: [new RegExp(j('\\b0x[0-9a-fA-F]', '{40}\\b'))]},
  [j('pay', 'sh')]: {names: [j('pay', 'sh'), j('pay', '.sh')], words: [], patterns: []},
  [j('ether', 'fuse')]: {names: [j('ether', 'fuse')], words: [], patterns: []},
};
// The only files in allowit-sdk that may name a vendor, and only on import or dependency lines.
const SDK_REGISTRATION = new Set([
  'Cargo.toml',
  'crates/allowit-sdk/Cargo.toml',
  'crates/allowit-sdk/src/plugins/registered.rs',
  'npm/package.json',
  'npm/src/registered.js',
]);
const REGISTRATION_LINE = [
  /^\s*(?:pub\s+)?(?:use|extern\s+crate)\s/, // Rust import
  /^\s*&[\w:]+::PLUGIN,?\s*$/, // Rust registration entry
  /^\s*export\s+\{[^}]*\}\s+from\s+['"][^'"]+['"];?\s*$/, // JS one-line registration
  /^\s*[\w-]+\s*=\s*\{.*\}\s*$/, // TOML dependency
  /^\s*\[(?:[\w.-]+\.)?(?:dev-)?dependencies\.[\w-]+\]\s*$/, // TOML dependency table
  /^\s*"[^"]+"\s*:\s*"[^"]*",?\s*$/, // package.json dependency
];
const LOCKFILES = new Set(['Cargo.lock', 'pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'bun.lockb']);
const PROSE = /\.(?:md|mdx)$/i;
const LEGAL = /(?:^|[-_.])(?:LICEN[CS]E|COPYING|NOTICE)(?:[-_.]|$)/i;

function subwords(text) {
  const out = [];
  for (const token of text.match(/[A-Za-z0-9]+/g) ?? []) {
    for (const part of token.split(/(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/)) out.push(part.toLowerCase());
  }
  return out;
}

/** Vendor terms in one line of text, as [{vendor, term}]. */
export function hits(line) {
  const found = [];
  const lower = line.toLowerCase();
  const words = new Set(subwords(line));
  for (const [vendor, rules] of Object.entries(VENDORS)) {
    for (const name of rules.names) if (lower.includes(name)) found.push({vendor, term: name});
    for (const word of rules.words) if (words.has(word)) found.push({vendor, term: word});
    for (const pattern of rules.patterns) {
      const m = line.match(pattern);
      if (m) found.push({vendor, term: m[0].length > 20 ? `${m[0].slice(0, 8)}...` : m[0]});
    }
  }
  return found;
}

/** Findings for one file under a role. `text` is null for a binary file. */
export function scanFile(path, text, config) {
  const name = basename(path);
  if (PROSE.test(path) || LEGAL.test(name)) return [];
  if (LOCKFILES.has(name) && !config.lockfiles) return [];
  const allowedVendors = new Set(config.role === 'vendor' ? config.vendors : []);
  const keep = (h) => !allowedVendors.has(h.vendor);
  const findings = hits(path).filter(keep).map((h) => ({path, line: 0, ...h}));
  if (text === null) return findings;
  text.split(/\r?\n/).forEach((line, index) => {
    let lineHits = hits(line).filter(keep);
    if (config.role === 'sdk' && SDK_REGISTRATION.has(path) && REGISTRATION_LINE.some((r) => r.test(line))) lineHits = [];
    for (const h of lineHits) findings.push({path, line: index + 1, ...h});
  });
  return findings;
}

function readConfig(root) {
  const file = join(root, 'vendor-boundary.json');
  if (!existsSync(file)) throw new Error('vendor-boundary.json is missing at the repository root');
  const config = JSON.parse(readFileSync(file, 'utf8'));
  const keys = Object.keys(config).sort().join(',');
  const valid =
    (config.role === 'shared' && ['role', 'lockfiles,role'].includes(keys) && [undefined, true].includes(config.lockfiles)) ||
    (config.role === 'sdk' && keys === 'role') ||
    (config.role === 'vendor' && keys === 'role,vendors' && Array.isArray(config.vendors) && config.vendors.length > 0 &&
      config.vendors.every((v) => Object.hasOwn(VENDORS, v)));
  if (!valid) throw new Error(`vendor-boundary.json is invalid: ${JSON.stringify(config)}`);
  return {lockfiles: false, vendors: [], ...config};
}

function repositoryFiles(root) {
  const out = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {cwd: root});
  return [...new Set(out.toString('utf8').split('\0').filter(Boolean))].filter((p) => existsSync(join(root, p)));
}

function load(root, path) {
  const bytes = readFileSync(join(root, path));
  return bytes.subarray(0, 8192).includes(0) ? null : bytes.toString('utf8');
}

export function scanRepository(root, extra = []) {
  const config = readConfig(root);
  if (basename(root) === 'allowit-sdk' && config.role !== 'sdk') throw new Error('allowit-sdk must use role sdk');
  const findings = [];
  let files = 0;
  for (const path of repositoryFiles(root)) {
    if (path === 'vendor-boundary.json') continue;
    findings.push(...scanFile(path, load(root, path), config));
    files += 1;
  }
  for (const [path, text] of extra) {
    findings.push(...scanFile(path, text, config));
    files += 1;
  }
  return {config, files, findings};
}

function report({config, files, findings}) {
  for (const f of findings.slice(0, 200)) console.log(`${f.path}:${f.line}: ${f.vendor} term "${f.term}"`);
  if (findings.length > 200) console.log(`... ${findings.length - 200} more`);
  const where = new Set(findings.map((f) => f.path)).size;
  console.log(`vendor-boundary: role=${config.role} files=${files} findings=${findings.length} in ${where} files`);
  return findings.length ? 1 : 0;
}

function selfTest() {
  const V = Object.keys(VENDORS);
  const shared = {role: 'shared', lockfiles: false, vendors: []};
  const sdk = {role: 'sdk', lockfiles: false, vendors: []};
  const vendor = {role: 'vendor', lockfiles: false, vendors: [V[0]]};
  const cases = [
    ['shared clean source', scanFile('src/lib.rs', 'pub fn transfer() {}\nlet temporary = 1;', shared), 0],
    ['shared vendor import', scanFile('src/lib.rs', `use ${V[0]}_sdk::Address;`, shared), 1],
    ['shared camelCase vendor', scanFile('src/App.tsx', `const ok = is${V[0][0].toUpperCase()}${V[0].slice(1)}Network(n);`, shared), 1],
    ['shared vendor word', scanFile('src/a.rs', `let transaction_${j('x', 'dr')} = 1;`, shared), 1],
    ['shared vendor path', scanFile(`ui/src/${V[1]}/wallet.ts`, 'export {}', shared), 1],
    ['shared vendor-shaped literal', scanFile('src/t.rs', `let a = "G${'A'.repeat(55)}";`, shared), 1],
    ['shared legal text ignored', scanFile('resources/source-LICENSE', `Copied from ${V[0]} sources.`, shared), 0],
    ['shared prose ignored', scanFile('README.md', `Runs on ${V[0]}.`, shared), 0],
    ['shared lockfile ignored', scanFile('Cargo.lock', `name = "${V[0]}-${j("x", "dr")}"`, shared), 0],
    ['shared lockfile scanned', scanFile('Cargo.lock', `name = "${V[0]}-${j("x", "dr")}"`, {...shared, lockfiles: true}), 1],
    ['sdk registration entry', scanFile('crates/allowit-sdk/src/plugins/registered.rs', `    &allowit_${V[0]}::PLUGIN,`, sdk), 0],
    ['sdk registration js', scanFile('npm/src/registered.js', `export {default as ${V[0]}} from '@allowit/${V[0]}/plugin';`, sdk), 0],
    ['sdk logic in registration file', scanFile('crates/allowit-sdk/src/plugins/registered.rs', `if id == "${V[0]}" {}`, sdk), 1],
    ['sdk vendor outside registration', scanFile('crates/allowit-sdk/src/execution.rs', `use allowit_${V[0]}::x;`, sdk), 1],
    ['vendor own terms', scanFile('src/lib.rs', `use ${V[0]}_${j("x", "dr")}::Limits;`, vendor), 0],
    ['vendor names another vendor', scanFile('src/lib.rs', `// ${V[1]} bridge`, vendor), 1],
  ];
  let failed = 0;
  for (const [name, findings, expected] of cases) {
    const ok = expected === 0 ? findings.length === 0 : findings.length > 0;
    if (!ok) failed += 1;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${name} (${findings.length} findings)`);
  }
  console.log(`vendor-boundary self-test: ${cases.length - failed}/${cases.length} passed`);
  return failed ? 1 : 0;
}

function main(argv) {
  if (argv.includes('--self-test')) return selfTest();
  const root = execFileSync('git', ['rev-parse', '--show-toplevel']).toString().trim();
  if (argv.includes('--probe')) {
    const allowed = readConfig(root).vendors;
    const name = Object.keys(VENDORS).find((v) => !allowed.includes(v));
    const probe = ['src/__vendor_boundary_probe__.rs', `use ${name}_sdk::Address;\n`];
    const clean = scanRepository(root);
    const probed = scanRepository(root, [probe]);
    const added = probed.findings.length - clean.findings.length;
    console.log(`probe: added ${probe[0]} with an import of a ${name} crate`);
    console.log(`probe: findings without probe=${clean.findings.length}, with probe=${probed.findings.length}`);
    for (const f of probed.findings.filter((f) => f.path === probe[0])) console.log(`probe: ${f.path}:${f.line}: ${f.vendor} term "${f.term}"`);
    const proved = added > 0;
    console.log(proved ? 'probe: PASS - the scan fails when a vendor name is added' : 'probe: FAIL - the added vendor name was not detected');
    return proved ? 0 : 1;
  }
  return report(scanRepository(root));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(`vendor-boundary: ${error.message}`);
    process.exitCode = 2;
  }
}
