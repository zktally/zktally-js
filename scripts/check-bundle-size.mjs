#!/usr/bin/env node
/**
 * Enforce the gzipped bundle budget.
 *
 * The demo site is a landing page, so load time is a real constraint rather
 * than an aspiration. Failing the build is the only way a size budget stays
 * true; a number in a document does not.
 *
 * Entry files are thin re-export stubs, so measuring them alone would report a
 * fraction of the real payload. Each budget therefore walks the entry's import
 * graph and measures every chunk a consumer actually downloads.
 */

import { readFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');

const BUDGETS = [
  { label: 'core', entries: ['index.js'], limit: 60 * 1024 },
  { label: 'core + worker', entries: ['index.js', 'zktally-worker.js'], limit: 75 * 1024 },
];

const IMPORT_RE = /(?:from|import)\s*["'](\.[^"']+)["']/g;

/** Every file reachable from `entry` through relative imports. */
async function graph(entry, seen = new Set()) {
  const path = resolve(dist, entry);
  if (seen.has(path)) return seen;
  seen.add(path);
  const source = await readFile(path, 'utf8');
  for (const [, specifier] of source.matchAll(IMPORT_RE)) {
    await graph(resolve(dirname(path), specifier), seen);
  }
  return seen;
}

let failed = false;
const kb = (n) => `${(n / 1024).toFixed(1)} kB`;

for (const { label, entries, limit } of BUDGETS) {
  const files = new Set();
  for (const entry of entries) for (const f of await graph(entry)) files.add(f);

  const sorted = [...files].sort();
  const contents = await Promise.all(sorted.map((f) => readFile(f)));
  const size = gzipSync(Buffer.concat(contents)).length;

  const ok = size <= limit;
  if (!ok) failed = true;
  console.log(
    `${ok ? 'ok  ' : 'FAIL'} ${label}: ${kb(size)} gzipped across ${sorted.length} file(s) (budget ${kb(limit)})`,
  );
}

if (failed) {
  console.error('\nbundle size budget exceeded');
  process.exit(1);
}
