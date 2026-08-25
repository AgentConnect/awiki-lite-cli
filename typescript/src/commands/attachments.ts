import { Command } from "commander";
import { readFileSync } from "node:fs";

import { AttachmentWorkflow } from "../application/attachments.js";
import { InvalidInputError } from "../application/errors.js";
import { AttachmentService } from "../infrastructure/attachment-service.js";
import { GroupService } from "../infrastructure/group-service.js";
import { MessageService } from "../infrastructure/message-service.js";
import { resolvePeerDid } from "../infrastructure/peer-resolver.js";
import { createRuntime, promptPassphrase, wrapMain } from "./runtime.js";

export function registerAttachmentCommand(root: Command): void {
  const attachment = root
    .command("attachment")
    .description("Download message attachments.");
  attachment
    .command("download")
    .requiredOption("--message-id <messageId>")
    .requiredOption("--attachment-id <attachmentId>")
    .requiredOption("--output <dir>")
    .action(
      (options: {
        messageId: string;
        attachmentId: string;
        output: string;
      }) => {
        wrapMain("attachment", async () => {
          const { settings, store, http } = createRuntime();
          try {
            const workflow = new AttachmentWorkflow(
              new AttachmentService(
                http.client,
                settings.messageServiceUrl,
                settings.allowPrivateNetwork,
              ),
              new MessageService(http.client, settings.messageServiceUrl),
              new GroupService(http.client, settings.messageServiceUrl),
              store,
            );
            const path = await workflow.download(
              { identity: store.loadPublic(), session: store.loadSession() },
              options.messageId,
              options.attachmentId,
              options.output,
            );
            console.log(`Downloaded attachment to ${path}`);
          } finally {
            http.close();
          }
        });
      },
    );
}

export async function sendAttachmentMessage(
  file: string,
  recipientDid: string | undefined,
  groupDid: string | undefined,
  text: string | undefined,
  stdin: boolean,
): Promise<void> {
  if ((recipientDid === undefined) === (groupDid === undefined)) {
    throw new InvalidInputError("choose exactly one of --to and --group");
  }
  if (stdin && text !== undefined) {
    throw new InvalidInputError("--text and --stdin are mutually exclusive");
  }
  const caption = stdin ? readFileSync(0, "utf8") : (text ?? null);
  const { settings, store, http } = createRuntime();
  try {
    const identity = store.loadPublic();
    const resolvedRecipient =
      recipientDid === undefined
        ? undefined
        : await resolvePeerDid(http.client, recipientDid, identity.handle, {
            allowPrivateNetwork: settings.allowPrivateNetwork,
          });
    const passphrase = await promptPassphrase();
    const workflow = new AttachmentWorkflow(
      new AttachmentService(
        http.client,
        settings.messageServiceUrl,
        settings.allowPrivateNetwork,
      ),
      new MessageService(http.client, settings.messageServiceUrl),
      new GroupService(http.client, settings.messageServiceUrl),
      store,
    );
    const [messageId, attachmentId] = await workflow.send(
      store.unlock(passphrase),
      file,
      {
        recipientDid: resolvedRecipient ?? null,
        groupDid: groupDid ?? null,
        caption,
      },
    );
    console.log(`Sent attachment ${attachmentId} in message ${messageId}`);
  } finally {
    http.close();
  }
}
