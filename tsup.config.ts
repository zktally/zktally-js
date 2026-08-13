import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    // The client handle consumers import.
    worker: 'src/worker/index.ts',
    // The worker body itself, loaded by URL from the client. It must be its own
    // entry: pointing the client at its own bundle would spawn a worker that
    // re-imports the client instead of the message loop.
    'zktally-worker': 'src/worker/worker.ts',
  },
  format: ['esm', 'cjs'],
  // Declarations come from `tsc --emitDeclarationOnly` instead: it emits one
  // .d.ts per module, mirroring src/, which is what the exports map's
  // ./dist/worker/index.d.ts entry points at. It is also an order of magnitude
  // faster than tsup's dts pass.
  dts: false,
  clean: true,
  treeshake: true,
  sourcemap: true,
  target: 'es2022',
  // The worker entry is ESM-only: a module worker cannot be loaded from CJS.
  outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.js' }),
});
