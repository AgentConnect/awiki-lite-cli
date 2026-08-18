import { mkdirSync, symlinkSync, unlinkSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));
const dest = join(root, 'node_modules', '.bin', 'awiki-lite-ts');
const target = resolve(root, 'bin/awiki-lite-ts.js');
mkdirSync(dirname(dest), { recursive: true });
try {
  unlinkSync(dest);
} catch {
  // first install
}
symlinkSync(relative(dirname(dest), target), dest);
