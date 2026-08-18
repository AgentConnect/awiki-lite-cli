import { Command } from 'commander';
import { readFileSync } from 'node:fs';

import { GroupWorkflow } from '../application/groups.js';
import { InvalidInputError } from '../application/errors.js';
import { parseManifest } from '../infrastructure/attachment-manifest.js';
import { GroupService } from '../infrastructure/group-service.js';
import { terminalText } from '../presentation.js';
import { createRuntime, promptPassphrase, wrapMain } from './runtime.js';

export function registerGroupCommand(root: Command): void {
  const group = root.command('group').description('Create and use transport-protected ordinary groups.');
  group.command('create').argument('<name>').action((name: string) => {
    wrapMain('group', async () => {
      const passphrase = await promptPassphrase();
      const { settings, store, http } = createRuntime();
      try {
        const workflow = new GroupWorkflow(new GroupService(http.client, settings.messageServiceUrl), store);
        const created = await workflow.create(store.unlock(passphrase), name);
        console.log(`Created ${created.displayName}: ${created.groupDid}`);
      } finally {
        http.close();
      }
    });
  });
  group.command('list').option('--limit <n>', 'Limit', (value) => Number(value), 20).option('--cursor <cursor>').action(
    (options: { limit: number; cursor?: string }) => {
      wrapMain('group', async () => {
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new GroupWorkflow(new GroupService(http.client, settings.messageServiceUrl), store);
          const [rows, next] = await workflow.listGroups(options.limit, options.cursor ?? null);
          for (const item of rows) {
            console.log(`${item.displayName}: ${item.groupDid}`);
          }
          if (next) {
            console.log(`Next cursor: ${next}`);
          }
        } finally {
          http.close();
        }
      });
    },
  );
  group.command('info').argument('<groupDid>').action((groupDid: string) => {
    wrapMain('group', async () => {
      const { settings, store, http } = createRuntime();
      try {
        const workflow = new GroupWorkflow(new GroupService(http.client, settings.messageServiceUrl), store);
        const item = await workflow.info(groupDid);
        console.log(`${item.displayName}: ${item.groupDid}`);
      } finally {
        http.close();
      }
    });
  });
  group.command('members').argument('<groupDid>').option('--limit <n>', 'Limit', (value) => Number(value), 20).option('--cursor <cursor>').action(
    (groupDid: string, options: { limit: number; cursor?: string }) => {
      wrapMain('group', async () => {
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new GroupWorkflow(new GroupService(http.client, settings.messageServiceUrl), store);
          const [rows, next] = await workflow.members(groupDid, options.limit, options.cursor ?? null);
          for (const item of rows) {
            console.log(`${item.agentDid} ${item.role} ${item.status}`);
          }
          if (next) {
            console.log(`Next cursor: ${next}`);
          }
        } finally {
          http.close();
        }
      });
    },
  );
  group.command('add').argument('<groupDid>').argument('<memberDid>').action((groupDid: string, memberDid: string) => {
    wrapMain('group', async () => {
      const passphrase = await promptPassphrase();
      const { settings, store, http } = createRuntime();
      try {
        const workflow = new GroupWorkflow(new GroupService(http.client, settings.messageServiceUrl), store);
        const added = await workflow.add(store.unlock(passphrase), groupDid, memberDid);
        console.log(`Added ${added} to ${groupDid}`);
      } finally {
        http.close();
      }
    });
  });
  group.command('send').argument('<groupDid>').argument('[text]').option('--stdin').action(
    (groupDid: string, text: string | undefined, options: { stdin?: boolean }) => {
      wrapMain('group', async () => {
        if (options.stdin && text !== undefined) {
          throw new InvalidInputError('TEXT and --stdin are mutually exclusive');
        }
        const textValue = options.stdin ? readFileSync(0, 'utf8') : text;
        if (!textValue) {
          throw new InvalidInputError('message text must not be empty');
        }
        const passphrase = await promptPassphrase();
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new GroupWorkflow(new GroupService(http.client, settings.messageServiceUrl), store);
          const message = await workflow.send(store.unlock(passphrase), groupDid, textValue);
          console.log(`Sent ${message.messageId} to ${message.groupDid}`);
        } finally {
          http.close();
        }
      });
    },
  );
  group.command('messages').argument('<groupDid>').option('--limit <n>', 'Limit', (value) => Number(value), 20).option('--since-seq <n>', 'Since seq', (value) => Number(value)).action(
    (groupDid: string, options: { limit: number; sinceSeq?: number }) => {
      wrapMain('group', async () => {
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new GroupWorkflow(new GroupService(http.client, settings.messageServiceUrl), store);
          const [rows, next] = await workflow.messages(groupDid, options.limit, options.sinceSeq ?? null);
          if (!rows.length) {
            console.log('No ordinary group messages.');
          }
          for (const message of rows) {
            if (message.messageType === 'attachment_manifest') {
              const [attachment, caption] = parseManifest(message.content);
              const suffix = caption ? ` caption=${terminalText(caption)}` : '';
              console.log(
                `[${message.groupEventSeq}] ${terminalText(message.senderDid)}: [attachment] ` +
                  `${terminalText(attachment.filename)} ` +
                  `id=${terminalText(attachment.attachmentId)} ` +
                  `message=${terminalText(message.messageId)}${suffix}`,
              );
            } else {
              const text =
                typeof message.content === 'object' && message.content !== null && 'text' in message.content
                  ? String((message.content as { text: unknown }).text)
                  : typeof message.content === 'string'
                    ? message.content
                    : '';
              console.log(
                `[${message.groupEventSeq}] ${terminalText(message.senderDid)}: ${terminalText(text)}`,
              );
            }
          }
          if (next !== null) {
            console.log(`Next since-seq: ${next}`);
          }
        } finally {
          http.close();
        }
      });
    },
  );
}
