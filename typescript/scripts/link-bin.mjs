import {
  chmodSync,
  mkdirSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(
  fileURLToPath(new URL("../package.json", import.meta.url)),
);
const dest = join(root, "node_modules", ".bin", "awiki-lite-ts");
const target = resolve(root, "bin/awiki-lite-ts.js");
mkdirSync(dirname(dest), { recursive: true });
for (const path of [dest, `${dest}.cmd`, `${dest}.ps1`]) {
  try {
    unlinkSync(path);
  } catch {
    // first install
  }
}
if (process.platform === "win32") {
  writeFileSync(
    `${dest}.cmd`,
    '@ECHO OFF\r\nnode "%~dp0\\..\\..\\bin\\awiki-lite-ts.js" %*\r\n',
  );
  writeFileSync(
    `${dest}.ps1`,
    '& node "$PSScriptRoot\\..\\..\\bin\\awiki-lite-ts.js" $args\r\n',
  );
} else {
  symlinkSync(relative(dirname(dest), target), dest);
  chmodSync(dest, 0o755);
}
