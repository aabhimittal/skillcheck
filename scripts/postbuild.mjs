// The probe shim is CommonJS and loaded via --require, so it is copied verbatim
// rather than compiled: it must not be touched by module transformation.
import { copyFileSync, chmodSync } from 'node:fs';
copyFileSync('src/probe/shim.cjs', 'dist/probe/shim.cjs');
copyFileSync('src/probe/sitecustomize.py', 'dist/probe/sitecustomize.py');
chmodSync('dist/cli.js', 0o755);
