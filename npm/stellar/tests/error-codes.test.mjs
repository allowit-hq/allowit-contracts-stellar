// Every typed code that the rail's browser package gives an error has an entry in Allowit's error catalogue
// (@allowit/core). A host shows the entry's title, the error's own message and the help page of the code; a word that
// is no catalogue code would reach the owner without a title and with the wrong help.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile, readdir} from 'node:fs/promises';
import {errorEntry} from '@allowit/core';

/** The source files of the package. */
async function sources(dir) {
  const out = [];
  for (const entry of await readdir(dir, {withFileTypes: true})) {
    const path = new URL(entry.name + (entry.isDirectory() ? '/' : ''), dir);
    if (entry.isDirectory()) out.push(...await sources(path));
    else if (entry.name.endsWith('.ts')) out.push([path.pathname, await readFile(path, 'utf8')]);
  }
  return out;
}
/**
 * The words where only a code can stand: `{code: 'word'}`, `new SetupRefusal('word', …)`, `new StepRefusal('word', …)`,
 * a `failure` fallback (`failure(error, 'word')`) and each word of the fallback's type (`fallback: 'one' | 'two'`).
 */
const codesIn = text => [
  ...[...text.matchAll(/\bcode:\s*'([^']+)'/g), ...text.matchAll(/new (?:SetupRefusal|StepRefusal)\('([^']+)'/g),
    ...text.matchAll(/\bfailure\([^,()]+,\s*'([^']+)'\)/g)].map(match => match[1]),
  ...[...text.matchAll(/\bfallback:\s*((?:'[^']+'\s*\|?\s*)+)/g)].flatMap(match => [...match[1].matchAll(/'([^']+)'/g)].map(word => word[1])),
];

test('the scan reads every form of a code', () => {
  assert.deepEqual(codesIn("throw Object.assign(new Error('x'), {code: 'one'}); new SetupRefusal('two', 'x'); new StepRefusal('three', 'x'); failure(error, 'four'); (error: unknown, fallback: 'five' | 'six')"),
    ['one', 'two', 'three', 'four', 'five', 'six']);
});

test('every code that the package gives an error has a catalogue entry', async () => {
  const found = (await sources(new URL('../src/', import.meta.url))).flatMap(([file, text]) => codesIn(text).map(code => [code, file]));
  assert.ok(found.length >= 8, 'the codes were not found');
  const missing = found.filter(([code]) => !errorEntry(code));
  assert.deepEqual(missing, [], 'these codes have no entry in the error catalogue of @allowit/core');
});
