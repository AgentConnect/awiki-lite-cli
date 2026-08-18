import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, test } from 'vitest';

import { createProgram } from '../src/cli.js';
import { CLIENT_IDENTIFIER, VERSION_LABEL } from '../src/version.js';

const here = dirname(fileURLToPath(import.meta.url));
const cliSource = join(here, '../src/cli.ts');

function runCli(args: string[]): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(process.execPath, ['--import', 'tsx', cliSource, ...args], {
    encoding: 'utf8',
    env: { ...process.env },
  });
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    status: result.status,
  };
}

describe('awiki-lite-ts help', () => {
  test('root help lists implemented commands twice consistently', () => {
    const first = runCli(['--help']);
    const second = runCli(['--help']);
    expect(first.status).toBe(0);
    expect(second.status).toBe(0);
    expect(first.stdout).toBe(second.stdout);
    for (const name of ['register', 'session', 'dm', 'group', 'attachment', 'listener']) {
      expect(first.stdout).toContain(name);
    }
  });

  test('version is the TypeScript label', () => {
    const first = runCli(['--version']);
    const second = runCli(['--version']);
    expect(first.stdout.trim()).toBe(VERSION_LABEL);
    expect(first.stdout).toBe(second.stdout);
    expect(first.stdout.trim()).not.toBe('0.2.0');
  });

  test('command help exposes contracted flags', () => {
    expect(runCli(['dm', 'send', '--help']).stdout).toContain('--stdin');
    expect(runCli(['attachment', 'send', '--help']).stdout).toContain('--to');
    expect(runCli(['attachment', 'send', '--help']).stdout).toContain('--group');
    expect(createProgram().name()).toBe('awiki-lite-ts');
    expect(CLIENT_IDENTIFIER).toBe('awiki-cli/0714/0.2.0');
  });
});
