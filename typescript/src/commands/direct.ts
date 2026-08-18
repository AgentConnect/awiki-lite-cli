import { Command } from 'commander';
import { readFileSync } from 'node:fs';

import { InvalidInputError, JsonRpcFailure } from '../application/errors.js';
import type { AttachmentContext, AuthenticatedIdentity, ChatMessage } from '../domain/models.js';
import { MessageService } from '../infrastructure/message-service.js';
import { operationFromSend, type SecureStateStore } from '../infrastructure/state.js';
import { terminalText } from '../presentation.js';
import { createRuntime, promptPassphrase, wrapMain } from './runtime.js';

export function registerDirectCommand(root: Command): void {
  const dm = root.command('dm').description('Send and read transport-protected direct messages.');
  dm.command('send')
    .argument('<did>', 'Recipient DID')
    .argument('[text]', 'Message text')
    .option('--stdin', 'Read message text from standard input.')
    .action((did: string, text: string | undefined, options: { stdin?: boolean }) => {
      wrapMain('messaging', async () => {
        if (options.stdin && text !== undefined) {
          throw new InvalidInputError('TEXT and --stdin are mutually exclusive');
        }
        const textValue = options.stdin ? readFileSync(0, 'utf8') : text;
        if (textValue === undefined) {
          throw new InvalidInputError('message text must not be empty');
        }
        const passphrase = await promptPassphrase();
        const { settings, store, http } = createRuntime();
        try {
          const identity = store.unlock(passphrase);
          const service = new MessageService(http.client, settings.messageServiceUrl);
          await service.ensureDirectBase(identity);
          const pending = store.prepareSend(did, textValue);
          try {
            const message = await service.send(
              identity,
              did,
              textValue,
              {
                operationId: pending.operationId,
                messageId: pending.messageId,
                createdAt: pending.createdAt,
                proofCreated: pending.proofCreated,
                proofNonce: pending.proofNonce,
              },
              false,
            );
            store.completeOperation(operationFromSend(pending));
            console.log(`Sent ${message.messageId} to ${message.targetDid}`);
          } catch (error) {
            if (error instanceof JsonRpcFailure) {
              store.abandonOperation(operationFromSend(pending));
            }
            throw error;
          }
        } finally {
          http.close();
        }
      });
    });

  dm.command('inbox')
    .option('--limit <n>', 'Limit', (value) => Number(value), 20)
    .option('--skip <n>', 'Skip', (value) => Number(value), 0)
    .option('--mark-read', 'Mark displayed messages read.')
    .action((options: { limit: number; skip: number; markRead?: boolean }) => {
      wrapMain('messaging', async () => {
        const { settings, store, http } = createRuntime();
        try {
          const identity: AuthenticatedIdentity = { identity: store.loadPublic(), session: store.loadSession() };
          const service = new MessageService(http.client, settings.messageServiceUrl);
          const [messages, hasMore] = await service.inbox(identity, options.limit, options.skip);
          saveAttachmentContextsFromMessages(store, messages);
          for (const line of renderDirectMessages(messages)) {
            console.log(line);
          }
          if (options.markRead && messages.length) {
            const updated = await service.markRead(
              identity,
              messages.map((item) => item.messageId),
            );
            console.log(`Marked ${updated} message(s) read.`);
          }
          if (hasMore) {
            console.log(`More messages are available; use --skip ${options.skip + options.limit}.`);
          }
        } finally {
          http.close();
        }
      });
    });

  dm.command('history')
    .argument('<did>', 'Peer DID')
    .option('--limit <n>', 'Limit', (value) => Number(value), 20)
    .option('--skip <n>', 'Skip', (value) => Number(value), 0)
    .action((did: string, options: { limit: number; skip: number }) => {
      wrapMain('messaging', async () => {
        const { settings, store, http } = createRuntime();
        try {
          const identity: AuthenticatedIdentity = { identity: store.loadPublic(), session: store.loadSession() };
          const service = new MessageService(http.client, settings.messageServiceUrl);
          const [messages, hasMore] = await service.history(identity, did, options.limit, options.skip);
          saveAttachmentContextsFromMessages(store, messages);
          for (const line of renderDirectMessages(messages)) {
            console.log(line);
          }
          if (hasMore) {
            console.log(`More messages are available; use --skip ${options.skip + options.limit}.`);
          }
        } finally {
          http.close();
        }
      });
    });
}

export function saveAttachmentContextsFromMessages(store: SecureStateStore, messages: ChatMessage[]): void {
  const contexts: AttachmentContext[] = [];
  for (const message of messages) {
    for (const attachment of message.attachments) {
      contexts.push({
        messageId: message.messageId,
        senderDid: message.senderDid,
        messageTargetDid: message.targetDid,
        groupDid: null,
        attachment,
      });
    }
  }
  store.saveAttachmentContexts(contexts);
}

export function renderDirectMessages(messages: ChatMessage[]): string[] {
  if (!messages.length) {
    return ['No plain direct messages.'];
  }
  return messages.map((message) => {
    const timestamp = message.createdAt ? `[${message.createdAt}] ` : '';
    if (message.attachments.length) {
      const attachment = message.attachments[0];
      const caption = message.caption ? ` caption=${terminalText(message.caption)}` : '';
      return (
        `${terminalText(timestamp)}${terminalText(message.senderDid)} -> ` +
        `${terminalText(message.targetDid)}: ` +
        `[attachment ${terminalText(attachment?.filename ?? '')} ` +
        `id=${terminalText(attachment?.attachmentId ?? '')} ` +
        `message=${terminalText(message.messageId)}]${caption}`
      );
    }
    return (
      `${terminalText(timestamp)}${terminalText(message.senderDid)} -> ` +
      `${terminalText(message.targetDid)}: ${terminalText(message.text)}`
    );
  });
}
