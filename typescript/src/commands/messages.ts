import { Command, Option } from "commander";

import { InvalidInputError } from "../application/errors.js";
import {
  registerAttachmentCommand,
  sendAttachmentMessage,
} from "./attachments.js";
import { registerDirectReadCommands, sendDirectMessage } from "./direct.js";
import { sendGroupMessage } from "./groups.js";
import { wrapMain } from "./runtime.js";

export function registerMessageCommand(root: Command): void {
  const message = root
    .command("msg")
    .description("Send and read transport-protected messages.");
  message
    .command("send")
    .description(
      "Send a direct or ordinary group text message or single attachment.",
    )
    .option("--to <peer>", "Direct peer DID or handle.")
    .option("--group <groupDid>", "Group target.")
    .option("--text <text>", "Inline message text or attachment caption.")
    .option("--file <file>", "Attachment file path.")
    .addOption(
      new Option(
        "--stdin",
        "Read text or caption from standard input.",
      ).hideHelp(),
    )
    .action(
      (options: {
        to?: string;
        group?: string;
        text?: string;
        file?: string;
        stdin?: boolean;
      }) => {
        const kind =
          options.file !== undefined
            ? "attachment"
            : options.group !== undefined
              ? "group"
              : "messaging";
        wrapMain(kind, async () => {
          if ((options.to === undefined) === (options.group === undefined)) {
            throw new InvalidInputError(
              "choose exactly one of --to and --group",
            );
          }
          if (options.file !== undefined) {
            await sendAttachmentMessage(
              options.file,
              options.to,
              options.group,
              options.text,
              Boolean(options.stdin),
            );
            return;
          }
          if (options.to !== undefined) {
            await sendDirectMessage(
              options.to,
              options.text,
              Boolean(options.stdin),
            );
            return;
          }
          if (options.group === undefined) {
            throw new InvalidInputError(
              "choose exactly one of --to and --group",
            );
          }
          await sendGroupMessage(
            options.group,
            options.text,
            Boolean(options.stdin),
          );
        });
      },
    );

  registerDirectReadCommands(message);
  registerAttachmentCommand(message);
}
