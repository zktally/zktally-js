#!/usr/bin/env node
/**
 * Mirror the vector corpus from the Python package.
 *
 * Vectors have exactly one source. Hand-editing the copy in this repo would let
 * the two ports drift while both suites stayed green, which is the one failure
 * mode a conformance corpus exists to prevent -- so this script verifies every
 * file against the manifest checksums and refuses to write on a mismatch.
 *
 * Usage: node scripts/sync-vectors.mjs [path-to-python-vectors]
 */

import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const destination = resolve(here, '..', 'test', 'vectors');
const source = resolve(
  process.argv[2] ?? join(here, '..', '..', 'zktally', 'tests', 'vectors'),
);

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

async function* walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    // Dot-entries are editor and tooling state, never vectors.
    if (entry.name.startsWith('.')) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else yield path;
  }
}

const manifestPath = join(source, 'manifest.json');
let manifest;
try {
  manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
} catch (cause) {
  console.error(`cannot read the source manifest at ${manifestPath}: ${cause.message}`);
  console.error('pass the path to the Python package\'s tests/vectors directory as an argument');
  process.exit(1);
}

const problems = [];
const copied = [];

for await (const path of walk(source)) {
  const name = relative(source, path).split('\\').join('/');
  const data = await readFile(path);
  if (name !== 'manifest.json') {
    const expected = manifest.files[name];
    if (!expected) {
      problems.push(`${name}: present on disk but absent from the manifest`);
      continue;
    }
    const actual = sha256(data);
    if (actual !== expected) {
      problems.push(`${name}: checksum ${actual} does not match manifest ${expected}`);
      continue;
    }
  }
  const target = join(destination, name);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, data);
  copied.push(name);
}

for (const name of Object.keys(manifest.files)) {
  if (!copied.includes(name)) problems.push(`${name}: in the manifest but missing from disk`);
}

if (problems.length > 0) {
  console.error('vector sync refused:');
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}

console.log(`synced ${copied.length} files at specVersion ${manifest.specVersion}`);
