import { createHash } from "node:crypto";
import { join } from "node:path";

import { InvalidInputError, JsonRpcFailure } from "./errors.js";
import { isRetryableTransportError } from "../infrastructure/rpc.js";
import { validateWbaDid } from "../domain/validation.js";
import { normalizeCaption } from "../infrastructure/attachment-manifest.js";
import {
  prepareFile,
  type AttachmentService,
} from "../infrastructure/attachment-service.js";
import type { GroupService } from "../infrastructure/group-service.js";
import type { MessageService } from "../infrastructure/message-service.js";
import type { SecureStateStore } from "../infrastructure/state.js";
import type {
  AuthenticatedIdentity,
  UnlockedIdentity,
} from "../domain/models.js";

export class AttachmentWorkflow {
  constructor(
    private readonly attachments: AttachmentService,
    private readonly direct: MessageService,
    private readonly groups: GroupService,
    private readonly store: SecureStateStore,
  ) {}

  async send(
    identity: UnlockedIdentity,
    filePath: string,
    options: {
      recipientDid: string | null;
      groupDid: string | null;
      caption: string | null;
    },
  ): Promise<[string, string]> {
    const [targetKind, targetDid, pendingKind] = target(
      options.recipientDid,
      options.groupDid,
    );
    const caption = normalizeCaption(options.caption);
    const capabilities = await this.attachments.capabilities(identity);
    if (targetKind === "agent") {
      await this.direct.ensureDirectBase(identity);
    } else {
      await this.groups.capabilities(identity);
    }
    const prepared = prepareFile(filePath, capabilities.maxObjectBytes);
    try {
      const input = inputDigest({
        target_kind: targetKind,
        target_did: targetDid,
        filename: prepared.filename,
        mime_type: prepared.mimeType,
        size: String(prepared.size),
        sha256_b64u: prepared.sha256B64u,
        caption: caption ?? "",
      });
      const stable = stableValues(
        identity.identity.did,
        pendingKind,
        targetDid,
        input,
      );
      const attachmentId = stable.attachment_id;
      const createOperationId = stable.create_operation_id;
      const commitOperationId = stable.commit_operation_id;
      const abortOperationId = stable.abort_operation_id;
      if (
        !attachmentId ||
        !createOperationId ||
        !commitOperationId ||
        !abortOperationId
      ) {
        throw new Error("stable pending values are incomplete");
      }
      let pending = this.store.prepareOperation(pendingKind, targetDid, input, {
        needsMessageId: true,
        values: stable,
        initialStage: "prepared",
      });
      let slot:
        Awaited<ReturnType<AttachmentService["createSlot"]>> | undefined;
      try {
        slot = await this.attachments.createSlot(
          identity,
          capabilities.serviceDid,
          attachmentId,
          prepared,
          targetKind,
          targetDid,
          createOperationId,
          pending.createdAt,
        );
      } catch (error) {
        if (error instanceof JsonRpcFailure) {
          this.store.abandonOperation(pending);
        }
        throw error;
      }
      if (pending.stage === "prepared") {
        try {
          await this.attachments.upload(slot, prepared);
          pending = this.store.advanceOperation(pending, "uploaded");
        } catch (error) {
          if (!isRetryableTransportError(error)) {
            await this.attachments.bestEffortAbort(
              identity,
              capabilities.serviceDid,
              slot,
              abortOperationId,
              pending.createdAt,
            );
            this.store.abandonOperation(pending);
          }
          throw error;
        }
      }
      let committed;
      try {
        committed = await this.attachments.commit(
          identity,
          capabilities.serviceDid,
          slot,
          prepared,
          commitOperationId,
          pending.createdAt,
        );
      } catch (error) {
        if (error instanceof JsonRpcFailure) {
          await this.attachments.bestEffortAbort(
            identity,
            capabilities.serviceDid,
            slot,
            abortOperationId,
            pending.createdAt,
          );
          this.store.abandonOperation(pending);
        }
        throw error;
      }
      if (pending.stage === "uploaded") {
        pending = this.store.advanceOperation(pending, "committed");
      }
      try {
        const message =
          targetKind === "agent"
            ? await this.direct.sendAttachment(
                identity,
                targetDid,
                committed.attachment,
                caption,
                pending,
              )
            : await this.groups.sendAttachment(
                identity,
                targetDid,
                committed.attachment,
                caption,
                pending,
              );
        this.store.completeOperation(pending);
        return [message.messageId, committed.attachment.attachmentId];
      } catch (error) {
        if (error instanceof JsonRpcFailure) {
          this.store.abandonOperation(pending);
        }
        throw error;
      }
    } finally {
      prepared.close();
    }
  }

  async download(
    identity: AuthenticatedIdentity,
    messageId: string,
    attachmentId: string,
    outputDir: string,
  ): Promise<string> {
    if (!messageId || !attachmentId) {
      throw new InvalidInputError(
        "message and attachment identifiers must not be empty",
      );
    }
    const context = this.store.loadAttachmentContext(messageId, attachmentId);
    const destination = join(outputDir, context.attachment.filename);
    const ticket = await this.attachments.getDownloadTicket(identity, context);
    return this.attachments.download(ticket, context.attachment, destination);
  }
}

function target(
  recipientDid: string | null,
  groupDid: string | null,
): [string, string, string] {
  if ((recipientDid === null) === (groupDid === null)) {
    throw new InvalidInputError("choose exactly one of --to and --group");
  }
  if (recipientDid !== null) {
    return ["agent", requireWbaDid(recipientDid), "direct.attachment.send"];
  }
  return [
    "group",
    requireWbaDid(groupDid ?? "", "group DID"),
    "group.attachment.send",
  ];
}

function requireWbaDid(value: string, field = "DID"): string {
  try {
    return validateWbaDid(value, field);
  } catch (error) {
    throw new InvalidInputError(
      error instanceof Error ? error.message : `${field} is invalid`,
    );
  }
}

function inputDigest(value: Record<string, string>): string {
  return createHash("sha256")
    .update(JSON.stringify(value, Object.keys(value).sort()))
    .digest("hex");
}

const NAMESPACE_URL = Buffer.from("6ba7b8119dad11d180b400c04fd430c8", "hex");

export function uuid5FromUrlName(name: string): string {
  const hash = createHash("sha1").update(NAMESPACE_URL).update(name).digest();
  hash[6] = ((hash[6] ?? 0) & 0x0f) | 0x50;
  hash[8] = ((hash[8] ?? 0) & 0x3f) | 0x80;
  const hex = hash.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function stableValues(
  senderDid: string,
  kind: string,
  targetDid: string,
  inputDigestValue: string,
): Record<string, string> {
  const base = `awiki-lite:v0.2:${senderDid}:${kind}:${targetDid}:${inputDigestValue}`;
  return {
    attachment_id: `att-${uuid5FromUrlName(`${base}:attachment`)}`,
    create_operation_id: uuid5FromUrlName(`${base}:create`),
    commit_operation_id: uuid5FromUrlName(`${base}:commit`),
    abort_operation_id: uuid5FromUrlName(`${base}:abort`),
  };
}
