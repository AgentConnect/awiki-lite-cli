import { createHash } from "node:crypto";

import { JsonRpcFailure } from "./errors.js";
import type {
  AttachmentContext,
  AuthenticatedIdentity,
  GroupMessage,
  GroupSummary,
} from "../domain/models.js";
import { validateWbaDid } from "../domain/validation.js";
import { parseManifest } from "../infrastructure/attachment-manifest.js";
import type { GroupService } from "../infrastructure/group-service.js";
import type { SecureStateStore } from "../infrastructure/state.js";
import type { UnlockedIdentity } from "../domain/models.js";

export class GroupWorkflow {
  constructor(
    private readonly service: GroupService,
    private readonly store: SecureStateStore,
  ) {}

  async create(
    identity: UnlockedIdentity,
    displayName: string,
  ): Promise<GroupSummary> {
    const name = displayName.trim();
    if (!name || name.length > 128) {
      throw new Error("group name must contain 1-128 characters");
    }
    const capabilities = await this.service.capabilities(identity);
    const maxMembers = Math.min(capabilities.maxMembers ?? 500, 500);
    const digest = inputDigest({
      display_name: name,
      max_members: String(maxMembers),
    });
    const pending = this.store.prepareOperation(
      "group.create",
      capabilities.serviceDid,
      digest,
      {
        needsMessageId: false,
      },
    );
    try {
      const result = await this.service.create(
        identity,
        capabilities.serviceDid,
        name,
        maxMembers,
        pending,
      );
      this.store.completeOperation(pending);
      return result;
    } catch (error) {
      if (error instanceof JsonRpcFailure) {
        this.store.abandonOperation(pending);
      }
      throw error;
    }
  }

  async add(
    identity: UnlockedIdentity,
    groupDid: string,
    memberDid: string,
  ): Promise<string> {
    const group = validateWbaDid(groupDid, "group DID");
    const member = validateWbaDid(memberDid);
    await this.service.capabilities(identity);
    const digest = inputDigest({ group_did: group, member_did: member });
    const pending = this.store.prepareOperation("group.add", group, digest, {
      needsMessageId: false,
    });
    try {
      const result = await this.service.add(identity, group, member, pending);
      this.store.completeOperation(pending);
      return result;
    } catch (error) {
      if (error instanceof JsonRpcFailure) {
        this.store.abandonOperation(pending);
      }
      throw error;
    }
  }

  async send(
    identity: UnlockedIdentity,
    groupDid: string,
    text: string,
  ): Promise<GroupMessage> {
    const group = validateWbaDid(groupDid, "group DID");
    if (!text || !text.trim()) {
      throw new Error("message text must not be empty");
    }
    const capabilities = await this.service.capabilities(identity);
    if (
      capabilities.maxGroupMessageBytes !== null &&
      Buffer.byteLength(text) > capabilities.maxGroupMessageBytes
    ) {
      throw new Error("message text exceeds the service Group message limit");
    }
    const digest = inputDigest({ group_did: group, text });
    const pending = this.store.prepareOperation("group.send", group, digest, {
      needsMessageId: true,
    });
    try {
      const result = await this.service.sendText(
        identity,
        group,
        text,
        pending,
      );
      this.store.completeOperation(pending);
      return result;
    } catch (error) {
      if (error instanceof JsonRpcFailure) {
        this.store.abandonOperation(pending);
      }
      throw error;
    }
  }

  async listGroups(limit: number, cursor: string | null) {
    return this.service.listGroups(this.authenticated(), limit, cursor);
  }

  async info(groupDid: string) {
    return this.service.info(this.authenticated(), groupDid);
  }

  async members(groupDid: string, limit: number, cursor: string | null) {
    return this.service.members(this.authenticated(), groupDid, limit, cursor);
  }

  async messages(groupDid: string, limit: number, sinceSeq: number | null) {
    const [rows, next] = await this.service.messages(
      this.authenticated(),
      groupDid,
      limit,
      sinceSeq,
    );
    const contexts: AttachmentContext[] = [];
    for (const message of rows) {
      if (message.messageType === "attachment_manifest") {
        const [attachment] = parseManifest(message.content);
        contexts.push({
          messageId: message.messageId,
          senderDid: message.senderDid,
          messageTargetDid: null,
          groupDid: message.groupDid,
          attachment,
        });
      }
    }
    this.store.saveAttachmentContexts(contexts);
    return [rows, next] as const;
  }

  private authenticated(): AuthenticatedIdentity {
    return {
      identity: this.store.loadPublic(),
      session: this.store.loadSession(),
    };
  }
}

export function inputDigest(value: Record<string, string>): string {
  return createHash("sha256")
    .update(JSON.stringify(value, Object.keys(value).sort()))
    .digest("hex");
}
