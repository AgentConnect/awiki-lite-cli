import { Command, Option } from "commander";
import { readFileSync } from "node:fs";

import { InvalidInputError, JsonRpcFailure } from "../application/errors.js";
import type {
  AttachmentContext,
  AuthenticatedIdentity,
  ChatMessage,
} from "../domain/models.js";
import { MessageService } from "../infrastructure/message-service.js";
import { resolvePeerDid } from "../infrastructure/peer-resolver.js";
import {
  operationFromSend,
  type SecureStateStore,
} from "../infrastructure/state.js";
import { terminalText } from "../presentation.js";
import {
  createRuntime,
  promptPassphrase,
  promptText,
  requireInteger,
  wrapMain,
} from "./runtime.js";

export async function sendDirectMessage(
  peer: string,
  text: string | undefined,
  stdin: boolean,
): Promise<void> {
  if (stdin && text !== undefined) {
    throw new InvalidInputError("--text and --stdin are mutually exclusive");
  }
  const textValue = stdin
    ? readFileSync(0, "utf8")
    : (text ?? (await promptText("Message")));
  const { settings, store, http } = createRuntime();
  try {
    const did = await resolvePeerDid(
      http.client,
      peer,
      store.loadPublic().handle,
      { allowPrivateNetwork: settings.allowPrivateNetwork },
    );
    const passphrase = await promptPassphrase();
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
}

export function registerDirectReadCommands(root: Command): void {
  root
    .command("inbox")
    .option("--limit <n>", "Limit", (value) => Number(value), 20)
    .addOption(
      new Option("--skip <n>", "Skip").argParser(Number).default(0).hideHelp(),
    )
    .option("--mark-read", "Mark displayed messages read.")
    .action((options: { limit: number; skip: number; markRead?: boolean }) => {
      wrapMain("messaging", async () => {
        requireInteger(options.limit, "limit", 1, 100);
        requireInteger(options.skip, "skip", 0);
        const { settings, store, http } = createRuntime();
        try {
          const identity: AuthenticatedIdentity = {
            identity: store.loadPublic(),
            session: store.loadSession(),
          };
          const service = new MessageService(
            http.client,
            settings.messageServiceUrl,
          );
          const [messages, hasMore] = await inboxWithSync(
            service,
            store,
            identity,
            options.limit,
            options.skip,
          );
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
            console.log(
              `More messages are available; use --skip ${options.skip + options.limit}.`,
            );
          }
        } finally {
          http.close();
        }
      });
    });

  root
    .command("history")
    .requiredOption("--with <peer>", "Direct peer DID or handle.")
    .option("--limit <n>", "Limit", (value) => Number(value), 50)
    .addOption(
      new Option("--skip <n>", "Skip").argParser(Number).default(0).hideHelp(),
    )
    .action((options: { with: string; limit: number; skip: number }) => {
      wrapMain("messaging", async () => {
        requireInteger(options.limit, "limit", 1, 100);
        requireInteger(options.skip, "skip", 0);
        const { settings, store, http } = createRuntime();
        try {
          const identity: AuthenticatedIdentity = {
            identity: store.loadPublic(),
            session: store.loadSession(),
          };
          const service = new MessageService(
            http.client,
            settings.messageServiceUrl,
          );
          const peer = await resolvePeerDid(
            http.client,
            options.with,
            identity.identity.handle,
            { allowPrivateNetwork: settings.allowPrivateNetwork },
          );
          const [messages, hasMore] = await historyWithSync(
            service,
            store,
            identity,
            peer,
            options.limit,
            options.skip,
          );
          saveAttachmentContextsFromMessages(store, messages);
          for (const line of renderDirectMessages(messages)) {
            console.log(line);
          }
          if (hasMore) {
            console.log(
              `More messages are available; use --skip ${options.skip + options.limit}.`,
            );
          }
        } finally {
          http.close();
        }
      });
    });
}

export function saveAttachmentContextsFromMessages(
  store: SecureStateStore,
  messages: ChatMessage[],
): void {
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

async function bootstrapTrackedInstallation(
  service: MessageService,
  store: SecureStateStore,
  identity: AuthenticatedIdentity,
): Promise<void> {
  const installation = store.loadSync(identity.identity.did);
  if (installation === null || installation.bootstrap !== null) {
    return;
  }
  const bootstrap = await service.bootstrapSync(
    identity,
    installation.clientInstanceId,
  );
  store.completeSyncBootstrap(installation, bootstrap);
}

export async function inboxWithSync(
  service: MessageService,
  store: SecureStateStore,
  identity: AuthenticatedIdentity,
  limit: number,
  skip: number,
): Promise<[ChatMessage[], boolean]> {
  await bootstrapTrackedInstallation(service, store, identity);
  const page = await service.inbox(identity, limit, skip);
  if (
    skip === 0 &&
    page[0].length === 0 &&
    !page[1] &&
    store.loadSync(identity.identity.did) === null
  ) {
    await bootstrapLegacyInstallation(service, store, identity);
    return service.inbox(identity, limit, skip);
  }
  return page;
}

export async function historyWithSync(
  service: MessageService,
  store: SecureStateStore,
  identity: AuthenticatedIdentity,
  peer: string,
  limit: number,
  skip: number,
): Promise<[ChatMessage[], boolean]> {
  await bootstrapTrackedInstallation(service, store, identity);
  const page = await service.history(identity, peer, limit, skip);
  if (
    skip === 0 &&
    page[0].length === 0 &&
    !page[1] &&
    store.loadSync(identity.identity.did) === null
  ) {
    await bootstrapLegacyInstallation(service, store, identity);
    return service.history(identity, peer, limit, skip);
  }
  return page;
}

async function bootstrapLegacyInstallation(
  service: MessageService,
  store: SecureStateStore,
  identity: AuthenticatedIdentity,
): Promise<void> {
  const installation = store.initializeSync(identity.identity.did);
  if (installation.bootstrap !== null) {
    return;
  }
  const bootstrap = await service.bootstrapSync(
    identity,
    installation.clientInstanceId,
  );
  store.completeSyncBootstrap(installation, bootstrap);
}

export function renderDirectMessages(messages: ChatMessage[]): string[] {
  if (!messages.length) {
    return ["No plain direct messages."];
  }
  return messages.map((message) => {
    const timestamp = message.createdAt ? `[${message.createdAt}] ` : "";
    if (message.attachments.length) {
      const attachment = message.attachments[0];
      const caption = message.caption
        ? ` caption=${terminalText(message.caption)}`
        : "";
      return (
        `${terminalText(timestamp)}${terminalText(message.senderDid)} -> ` +
        `${terminalText(message.targetDid)}: ` +
        `[attachment ${terminalText(attachment?.filename ?? "")} ` +
        `id=${terminalText(attachment?.attachmentId ?? "")} ` +
        `message=${terminalText(message.messageId)}]${caption}`
      );
    }
    return (
      `${terminalText(timestamp)}${terminalText(message.senderDid)} -> ` +
      `${terminalText(message.targetDid)}: ${terminalText(message.text)}`
    );
  });
}
