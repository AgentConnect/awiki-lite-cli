import { Command } from 'commander';
import { readFileSync } from 'node:fs';

import { AttachmentWorkflow } from '../application/attachments.js';
import { InvalidInputError } from '../application/errors.js';
import { AttachmentService } from '../infrastructure/attachment-service.js';
import { GroupService } from '../infrastructure/group-service.js';
import { MessageService } from '../infrastructure/message-service.js';
import { createRuntime, promptPassphrase, wrapMain } from './runtime.js';

export function registerAttachmentCommand(root: Command): void {
  const attachment = root.command('attachment').description('Send and download one plain transport-protected attachment.');
  attachment
    .command('send')
    .argument('<file>')
    .option('--to <did>')
    .option('--group <groupDid>')
    .option('--caption <caption>')
    .option('--caption-stdin')
    .action(
      (
        file: string,
        options: { to?: string; group?: string; caption?: string; captionStdin?: boolean },
      ) => {
        wrapMain('attachment', async () => {
          if ((options.to === undefined) === (options.group === undefined)) {
            throw new InvalidInputError('choose exactly one of --to and --group');
          }
          if (options.captionStdin && options.caption !== undefined) {
            throw new InvalidInputError('--caption and --caption-stdin are mutually exclusive');
          }
          const caption = options.captionStdin ? readFileSync(0, 'utf8') : (options.caption ?? null);
          const passphrase = await promptPassphrase();
          const { settings, store, http } = createRuntime();
          try {
            const workflow = new AttachmentWorkflow(
              new AttachmentService(http.client, settings.messageServiceUrl),
              new MessageService(http.client, settings.messageServiceUrl),
              new GroupService(http.client, settings.messageServiceUrl),
              store,
            );
            const [messageId, attachmentId] = await workflow.send(store.unlock(passphrase), file, {
              recipientDid: options.to ?? null,
              groupDid: options.group ?? null,
              caption,
            });
            console.log(`Sent attachment ${attachmentId} as ${messageId}`);
          } finally {
            http.close();
          }
        });
      },
    );
  attachment
    .command('download')
    .argument('<messageId>')
    .argument('<attachmentId>')
    .requiredOption('--output <dir>')
    .action((messageId: string, attachmentId: string, options: { output: string }) => {
      wrapMain('attachment', async () => {
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new AttachmentWorkflow(
            new AttachmentService(http.client, settings.messageServiceUrl),
            new MessageService(http.client, settings.messageServiceUrl),
            new GroupService(http.client, settings.messageServiceUrl),
            store,
          );
          const path = await workflow.download(
            { identity: store.loadPublic(), session: store.loadSession() },
            messageId,
            attachmentId,
            options.output,
          );
          console.log(`Downloaded ${path}`);
        } finally {
          http.close();
        }
      });
    });
}
