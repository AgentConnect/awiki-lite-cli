#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { Command } from 'commander';

import { registerAttachmentCommand } from './commands/attachments.js';
import { registerDirectCommand } from './commands/direct.js';
import { registerGroupCommand } from './commands/groups.js';
import { registerIdentityCommand } from './commands/identity.js';
import { registerListenerCommand } from './commands/listener.js';
import { registerSessionCommand } from './commands/session.js';
import { VERSION_LABEL } from './version.js';

export function createProgram(): Command {
  const program = new Command();
  program
    .name('awiki-lite-ts')
    .description('TypeScript AWiki Lite CLI for registration, messaging, groups, and attachments.')
    .version(VERSION_LABEL, '-V, --version', 'Show the TypeScript package version and exit.');
  registerIdentityCommand(program);
  registerSessionCommand(program);
  registerDirectCommand(program);
  registerGroupCommand(program);
  registerAttachmentCommand(program);
  registerListenerCommand(program);
  return program;
}

export function run(argv: string[] = process.argv): void {
  createProgram().parse(argv);
}

function isDirectInvocation(): boolean {
  const entry = process.argv[1];
  if (!entry) {
    return false;
  }
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}

if (isDirectInvocation()) {
  run();
}
