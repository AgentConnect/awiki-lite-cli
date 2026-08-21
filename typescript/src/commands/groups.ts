import { Command, Option } from "commander";
import { readFileSync } from "node:fs";

import { GroupWorkflow } from "../application/groups.js";
import { InvalidInputError } from "../application/errors.js";
import { parseManifest } from "../infrastructure/attachment-manifest.js";
import { GroupService } from "../infrastructure/group-service.js";
import { resolvePeerDid } from "../infrastructure/peer-resolver.js";
import { terminalText } from "../presentation.js";
import {
  createRuntime,
  promptPassphrase,
  promptText,
  requireInteger,
  requireNonemptyText,
  wrapMain,
} from "./runtime.js";

export function registerGroupCommand(root: Command): void {
  const group = root
    .command("group")
    .description("Create and use transport-protected ordinary groups.");
  group
    .command("create")
    .requiredOption("--name <name>")
    .action((options: { name: string }) => {
      wrapMain("group", async () => {
        const passphrase = await promptPassphrase();
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new GroupWorkflow(
            new GroupService(http.client, settings.messageServiceUrl),
            store,
          );
          const created = await workflow.create(
            store.unlock(passphrase),
            options.name,
          );
          console.log(`Created ${created.displayName}: ${created.groupDid}`);
        } finally {
          http.close();
        }
      });
    });
  group
    .command("list")
    .option("--limit <n>", "Limit", (value) => Number(value), 50)
    .addOption(new Option("--cursor <cursor>").hideHelp())
    .action((options: { limit: number; cursor?: string }) => {
      wrapMain("group", async () => {
        requireInteger(options.limit, "limit", 1, 100);
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new GroupWorkflow(
            new GroupService(http.client, settings.messageServiceUrl),
            store,
          );
          const [rows, next] = await workflow.listGroups(
            options.limit,
            options.cursor ?? null,
          );
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
    });
  group
    .command("get")
    .requiredOption("--group <groupDid>")
    .action((options: { group: string }) => {
      wrapMain("group", async () => {
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new GroupWorkflow(
            new GroupService(http.client, settings.messageServiceUrl),
            store,
          );
          const item = await workflow.info(options.group);
          console.log(`${item.displayName}: ${item.groupDid}`);
        } finally {
          http.close();
        }
      });
    });
  group
    .command("members")
    .requiredOption("--group <groupDid>")
    .option("--limit <n>", "Limit", (value) => Number(value), 100)
    .addOption(new Option("--cursor <cursor>").hideHelp())
    .action((options: { group: string; limit: number; cursor?: string }) => {
      wrapMain("group", async () => {
        requireInteger(options.limit, "limit", 1, 100);
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new GroupWorkflow(
            new GroupService(http.client, settings.messageServiceUrl),
            store,
          );
          const [rows, next] = await workflow.members(
            options.group,
            options.limit,
            options.cursor ?? null,
          );
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
    });
  group
    .command("add")
    .requiredOption("--group <groupDid>")
    .requiredOption("--member <peer>", "Member DID or handle.")
    .action((options: { group: string; member: string }) => {
      wrapMain("group", async () => {
        const { settings, store, http } = createRuntime();
        try {
          const member = await resolvePeerDid(
            http.client,
            options.member,
            store.loadPublic().handle,
            { allowPrivateNetwork: settings.allowPrivateNetwork },
          );
          const passphrase = await promptPassphrase();
          const workflow = new GroupWorkflow(
            new GroupService(http.client, settings.messageServiceUrl),
            store,
          );
          const added = await workflow.add(
            store.unlock(passphrase),
            options.group,
            member,
          );
          console.log(`Added ${added} to ${options.group}`);
        } finally {
          http.close();
        }
      });
    });
  group
    .command("messages")
    .requiredOption("--group <groupDid>")
    .option("--limit <n>", "Limit", (value) => Number(value), 50)
    .addOption(
      new Option("--since-seq <n>", "Since seq").argParser(Number).hideHelp(),
    )
    .action((options: { group: string; limit: number; sinceSeq?: number }) => {
      wrapMain("group", async () => {
        requireInteger(options.limit, "limit", 1, 100);
        if (options.sinceSeq !== undefined) {
          requireInteger(options.sinceSeq, "since-seq", 0);
        }
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new GroupWorkflow(
            new GroupService(http.client, settings.messageServiceUrl),
            store,
          );
          const [rows, next] = await workflow.messages(
            options.group,
            options.limit,
            options.sinceSeq ?? null,
          );
          if (!rows.length) {
            console.log("No ordinary group messages.");
          }
          for (const message of rows) {
            if (message.messageType === "attachment_manifest") {
              const [attachment, caption] = parseManifest(message.content);
              const suffix = caption ? ` caption=${terminalText(caption)}` : "";
              console.log(
                `[${message.groupEventSeq}] ${terminalText(message.senderDid)}: [attachment] ` +
                  `${terminalText(attachment.filename)} ` +
                  `id=${terminalText(attachment.attachmentId)} ` +
                  `message=${terminalText(message.messageId)}${suffix}`,
              );
            } else {
              const text =
                typeof message.content === "object" &&
                message.content !== null &&
                "text" in message.content
                  ? String((message.content as { text: unknown }).text)
                  : typeof message.content === "string"
                    ? message.content
                    : "";
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
    });
}

export async function sendGroupMessage(
  groupDid: string,
  text: string | undefined,
  stdin: boolean,
): Promise<void> {
  if (stdin && text !== undefined) {
    throw new InvalidInputError("--text and --stdin are mutually exclusive");
  }
  const textValue = requireNonemptyText(
    stdin ? readFileSync(0, "utf8") : (text ?? (await promptText("Message"))),
  );
  const passphrase = await promptPassphrase();
  const { settings, store, http } = createRuntime();
  try {
    const workflow = new GroupWorkflow(
      new GroupService(http.client, settings.messageServiceUrl),
      store,
    );
    const message = await workflow.send(
      store.unlock(passphrase),
      groupDid,
      textValue,
    );
    console.log(`Sent ${message.messageId} to ${message.groupDid}`);
  } finally {
    http.close();
  }
}
