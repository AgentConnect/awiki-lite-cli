import type {
  AttachmentRef,
  AuthenticatedIdentity,
  GroupMember,
  GroupMessage,
  GroupSummary,
  PendingOperation,
  UnlockedIdentity,
} from "../domain/models.js";
import { ProtocolResponseError } from "../application/errors.js";
import { generateOriginProof } from "./anp-sdk.js";
import {
  MANIFEST_CONTENT_TYPE,
  buildManifest,
  parseManifest,
} from "./attachment-manifest.js";
import {
  buildCapabilities,
  ORIGIN_SCHEME,
  validateDid,
} from "./message-service.js";
import {
  callJsonRpc,
  isRetryableTransportError,
  type HttpClient,
} from "./rpc.js";

export const GROUP_PROFILE = "anp.group.base.v1";
export const GROUP_LOCAL_PROFILE = "anp.group.local.v1";
export const LITE_MAX_GROUP_MEMBERS = 500;

export interface GroupCapabilities {
  readonly serviceDid: string;
  readonly maxGroupMessageBytes: number | null;
  readonly maxMembers: number | null;
}

export function resolveMaxMembers(advertised: number | null): number {
  return Math.min(advertised ?? LITE_MAX_GROUP_MEMBERS, LITE_MAX_GROUP_MEMBERS);
}

export function buildGroupCreate(
  identity: UnlockedIdentity,
  serviceDid: string,
  displayName: string,
  maxMembers: number,
  pending: PendingOperation,
): Record<string, unknown> {
  const name = displayName.trim();
  if (!name || name.length > 128) {
    throw new Error("group name must contain 1-128 characters");
  }
  return signedGroupParams(
    identity,
    "group.create",
    "service",
    validateDid(serviceDid),
    "application/json",
    {
      group_profile: { display_name: name, discoverability: "private" },
      group_policy: {
        message_security_profile: "transport-protected",
        bootstrap_security_profile: "transport-protected",
        admission_mode: "admin-add",
        permissions: {
          send: "member",
          add: "admin",
          remove: "admin",
          update_profile: "admin",
          update_policy: "owner",
        },
        attachments_allowed: true,
        max_members: String(maxMembers),
      },
    },
    pending,
  );
}

export function buildGroupAdd(
  identity: UnlockedIdentity,
  groupDid: string,
  memberDid: string,
  pending: PendingOperation,
): Record<string, unknown> {
  return signedGroupParams(
    identity,
    "group.add",
    "group",
    validateDid(groupDid, "group DID"),
    "application/json",
    { member_did: validateDid(memberDid), role: "member" },
    pending,
  );
}

export function buildGroupSendText(
  identity: UnlockedIdentity,
  groupDid: string,
  text: string,
  pending: PendingOperation,
): Record<string, unknown> {
  if (!text || !text.trim()) {
    throw new Error("message text must not be empty");
  }
  return signedGroupParams(
    identity,
    "group.send",
    "group",
    validateDid(groupDid, "group DID"),
    "text/plain",
    { text },
    pending,
  );
}

export function buildGroupSendAttachment(
  identity: UnlockedIdentity,
  groupDid: string,
  attachment: AttachmentRef,
  caption: string | null,
  pending: PendingOperation,
): Record<string, unknown> {
  if (pending.kind !== "group.attachment.send") {
    throw new Error(
      "pending operation does not match the Group attachment request",
    );
  }
  return signedGroupParams(
    identity,
    "group.send",
    "group",
    validateDid(groupDid, "group DID"),
    MANIFEST_CONTENT_TYPE,
    { payload: buildManifest(attachment, caption) },
    pending,
    "group.attachment.send",
  );
}

function signedGroupParams(
  identity: UnlockedIdentity,
  method: string,
  targetKind: string,
  targetDid: string,
  contentType: string,
  body: Record<string, unknown>,
  pending: PendingOperation,
  pendingKind?: string,
): Record<string, unknown> {
  if (
    pending.kind !== (pendingKind ?? method) ||
    pending.targetDid !== targetDid
  ) {
    throw new Error("pending operation does not match the Group request");
  }
  const meta: Record<string, unknown> = {
    profile: GROUP_PROFILE,
    security_profile: "transport-protected",
    sender_did: identity.identity.did,
    target: { kind: targetKind, did: targetDid },
    operation_id: pending.operationId,
    created_at: pending.createdAt,
    content_type: contentType,
  };
  if (method === "group.send") {
    if (pending.messageId === null) {
      throw new Error("Group send requires a message id");
    }
    meta.message_id = pending.messageId;
  }
  const proof = generateOriginProof(
    method,
    meta,
    body,
    identity.deviceSigningPrivateKeyPem,
    identity.identity.verificationMethod,
    { created: pending.proofCreated, nonce: pending.proofNonce },
  );
  return { meta, auth: { scheme: ORIGIN_SCHEME, origin_proof: proof }, body };
}

export class GroupService {
  readonly endpoint: string;

  constructor(
    private readonly client: HttpClient,
    baseUrl: string,
  ) {
    this.endpoint = `${baseUrl.replace(/\/+$/, "")}/im/rpc`;
  }

  async capabilities(
    identity: AuthenticatedIdentity | UnlockedIdentity,
  ): Promise<GroupCapabilities> {
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        "anp.get_capabilities",
        buildCapabilities(identity.identity.did),
        {
          accessToken: identity.session.accessToken,
        },
      ),
    );
    requireAdvertised(result, "supported_profiles", GROUP_PROFILE);
    requireAdvertised(
      result,
      "supported_security_profiles",
      "transport-protected",
    );
    requireAdvertised(result, "supported_content_types", "text/plain");
    const serviceDid = result.service_did;
    if (typeof serviceDid !== "string") {
      throw new Error("message service did is unavailable");
    }
    const limits = asMaybeObject(result.limits);
    const features = asMaybeObject(result.features);
    const participant = features
      ? asMaybeObject(features.group_participant)
      : null;
    return {
      serviceDid: validateDid(serviceDid),
      maxGroupMessageBytes: optionalPositiveInt(
        limits,
        "max_group_message_bytes",
      ),
      maxMembers: optionalPositiveInt(participant, "max_members"),
    };
  }

  async create(
    identity: UnlockedIdentity,
    serviceDid: string,
    name: string,
    maxMembers: number,
    pending: PendingOperation,
  ): Promise<GroupSummary> {
    const result = await this.mutate(
      identity,
      "group.create",
      buildGroupCreate(identity, serviceDid, name, maxMembers, pending),
    );
    return parseGroupSummary(result);
  }

  async add(
    identity: UnlockedIdentity,
    groupDid: string,
    memberDid: string,
    pending: PendingOperation,
  ): Promise<string> {
    const group = validateDid(groupDid, "group DID");
    const member = validateDid(memberDid);
    const result = await this.mutate(
      identity,
      "group.add",
      buildGroupAdd(identity, group, member, pending),
    );
    if (result.group_did !== group || result.member_did !== member) {
      throw new Error("service returned mismatched group.add identifiers");
    }
    return member;
  }

  async sendText(
    identity: UnlockedIdentity,
    groupDid: string,
    text: string,
    pending: PendingOperation,
  ): Promise<GroupMessage> {
    const group = validateDid(groupDid, "group DID");
    const result = await this.mutate(
      identity,
      "group.send",
      buildGroupSendText(identity, group, text, pending),
    );
    if (
      result.group_did !== group ||
      result.message_id !== pending.messageId ||
      result.operation_id !== pending.operationId
    ) {
      throw new Error("service returned mismatched group.send identifiers");
    }
    return {
      messageId: requiredString(result, "message_id"),
      groupDid: group,
      senderDid: identity.identity.did,
      messageType: "text",
      content: text,
      contentType: "text/plain",
      groupEventSeq: positiveInt(result.group_event_seq, "group_event_seq"),
      createdAt: requiredString(result, "accepted_at"),
    };
  }

  async sendAttachment(
    identity: UnlockedIdentity,
    groupDid: string,
    attachment: AttachmentRef,
    caption: string | null,
    pending: PendingOperation,
  ): Promise<GroupMessage> {
    const group = validateDid(groupDid, "group DID");
    const result = await this.mutate(
      identity,
      "group.send",
      buildGroupSendAttachment(identity, group, attachment, caption, pending),
    );
    if (
      result.group_did !== group ||
      result.message_id !== pending.messageId ||
      result.operation_id !== pending.operationId
    ) {
      throw new Error("service returned mismatched group.send identifiers");
    }
    return {
      messageId: requiredString(result, "message_id"),
      groupDid: group,
      senderDid: identity.identity.did,
      messageType: "attachment_manifest",
      content: buildManifest(attachment, caption),
      contentType: MANIFEST_CONTENT_TYPE,
      groupEventSeq: positiveInt(result.group_event_seq, "group_event_seq"),
      createdAt: requiredString(result, "accepted_at"),
    };
  }

  async listGroups(
    identity: AuthenticatedIdentity,
    limit: number,
    cursor: string | null,
  ): Promise<[GroupSummary[], string | null]> {
    const body: Record<string, unknown> = { limit: requireLimit(limit) };
    if (cursor !== null) {
      if (!cursor || cursor.length > 4096) {
        throw new Error("cursor must contain 1-4096 characters");
      }
      body.cursor = cursor;
    }
    const result = await this.read(identity, "group.list", {
      meta: {
        profile: GROUP_LOCAL_PROFILE,
        security_profile: "transport-protected",
        sender_did: identity.identity.did,
      },
      body,
    });
    const items = requiredList(result, "groups")
      .map((item) => asObject(item))
      .filter((row) => isPlainGroup(row))
      .map((row) => parseGroupSummary(row));
    return [items, nextCursor(result)];
  }

  async info(
    identity: AuthenticatedIdentity,
    groupDid: string,
  ): Promise<GroupSummary> {
    const group = validateDid(groupDid, "group DID");
    const result = await this.read(identity, "group.get_info", {
      meta: {
        profile: GROUP_PROFILE,
        security_profile: "transport-protected",
        sender_did: identity.identity.did,
        target: { kind: "group", did: group },
      },
      body: { include_policy: true, include_member_list: false },
    });
    if (!isPlainGroup(result)) {
      throw new Error(
        "group does not use the supported transport-protected profile",
      );
    }
    return parseGroupSummary(result);
  }

  async members(
    identity: AuthenticatedIdentity,
    groupDid: string,
    limit: number,
    cursor: string | null,
  ): Promise<[GroupMember[], string | null]> {
    const group = validateDid(groupDid, "group DID");
    const body: Record<string, unknown> = {
      group_did: group,
      limit: requireLimit(limit),
    };
    if (cursor !== null) {
      if (!cursor || cursor.length > 4096) {
        throw new Error("cursor must contain 1-4096 characters");
      }
      body.cursor = cursor;
    }
    const result = await this.read(identity, "group.list_members", {
      meta: {
        profile: GROUP_LOCAL_PROFILE,
        security_profile: "transport-protected",
        sender_did: identity.identity.did,
        target: { kind: "group", did: group },
      },
      body,
    });
    if (result.group_did !== group) {
      throw new Error("service returned mismatched group member identifiers");
    }
    const rows = requiredList(result, "members").map((item) => {
      const row = asObject(item);
      return {
        agentDid: responseDid(row, "agent_did"),
        role: requiredString(row, "role"),
        status: requiredString(row, "status"),
      };
    });
    return [rows, nextCursor(result)];
  }

  async messages(
    identity: AuthenticatedIdentity,
    groupDid: string,
    limit: number,
    sinceSeq: number | null,
  ): Promise<[GroupMessage[], number | null]> {
    const group = validateDid(groupDid, "group DID");
    if (sinceSeq !== null && sinceSeq < 0) {
      throw new Error("since-seq must not be negative");
    }
    const body: Record<string, unknown> = {
      group_did: group,
      limit: requireLimit(limit),
    };
    if (sinceSeq !== null) {
      body.since_seq = sinceSeq;
    }
    const result = await this.read(identity, "group.list_messages", {
      meta: {
        profile: GROUP_LOCAL_PROFILE,
        security_profile: "transport-protected",
        sender_did: identity.identity.did,
        target: { kind: "group", did: group },
      },
      body,
    });
    const rows: GroupMessage[] = [];
    for (const item of requiredList(result, "messages")) {
      const row = asObject(item);
      if (row.type !== "text" && row.type !== "attachment_manifest") {
        continue;
      }
      if (row.group_did !== group) {
        throw new Error("service returned a message for a different group");
      }
      const content = row.content;
      if (row.type === "attachment_manifest") {
        if (row.content_type !== MANIFEST_CONTENT_TYPE) {
          throw new Error("service returned an invalid attachment projection");
        }
        parseManifest(content);
      } else if (
        row.content_type !== "text/plain" ||
        typeof content !== "string"
      ) {
        throw new Error("service returned an invalid Group text projection");
      }
      rows.push({
        messageId: requiredString(row, "message_id"),
        groupDid: responseDid(row, "group_did"),
        senderDid: responseDid(row, "sender_did"),
        messageType: requiredString(row, "type"),
        content,
        contentType: requiredString(row, "content_type"),
        groupEventSeq: positiveInt(row.group_event_seq, "group_event_seq"),
        createdAt: optionalTimestamp(row),
      });
    }
    const next =
      result.next_since_seq === undefined || result.next_since_seq === null
        ? null
        : positiveInt(result.next_since_seq, "next_since_seq");
    return [rows, next];
  }

  private async mutate(
    identity: UnlockedIdentity,
    method: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const result = asObject(
          await callJsonRpc(this.client, this.endpoint, method, params, {
            accessToken: identity.session.accessToken,
          }),
        );
        if (
          result.accepted !== true &&
          (result.accepted !== undefined ||
            !["group.create", "group.add"].includes(method) ||
            result.group_receipt === undefined ||
            result.group_receipt === null)
        ) {
          throw new Error(`service returned an invalid ${method} result`);
        }
        validateMutationResult(method, params, result);
        return result;
      } catch (error) {
        lastError = error;
        if (!isRetryableTransportError(error) || attempt === 1) {
          throw error;
        }
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new Error(`service returned an invalid ${method} result`);
  }

  private async read(
    identity: AuthenticatedIdentity,
    method: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return asObject(
      await callJsonRpc(this.client, this.endpoint, method, params, {
        accessToken: identity.session.accessToken,
      }),
    );
  }
}

function requiredString(row: Record<string, unknown>, field: string): string {
  const value = row[field];
  if (typeof value !== "string" || !value) {
    throw new ProtocolResponseError(`service returned invalid ${field}`);
  }
  return value;
}

function optionalString(
  row: Record<string, unknown>,
  field: string,
): string | null {
  const value = row[field];
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new ProtocolResponseError(`service returned invalid ${field}`);
  }
  return typeof value === "string" ? value : null;
}

function requireLimit(value: number): number {
  if (value < 1 || value > 100) {
    throw new Error("limit must be between 1 and 100");
  }
  return value;
}

function requireAdvertised(
  result: Record<string, unknown>,
  field: string,
  required: string,
): void {
  const advertised = result[field];
  if (!Array.isArray(advertised) || !advertised.includes(required)) {
    throw new Error(`message service does not advertise required ${required}`);
  }
}

function parseGroupSummary(value: Record<string, unknown>): GroupSummary {
  const groupDid = responseDid(value, "group_did");
  const profile = value.group_profile;
  let name: unknown = value.name;
  if (
    typeof profile === "object" &&
    profile !== null &&
    !Array.isArray(profile)
  ) {
    name = (profile as Record<string, unknown>).display_name ?? name;
  }
  if (typeof name !== "string" || !name) {
    throw new Error("service returned a group without a display name");
  }
  return {
    groupDid,
    displayName: name,
    groupStateVersion: String(
      positiveInt(value.group_state_version, "group_state_version"),
    ),
    memberCount: nonnegativeInt(value.member_count ?? 1, "member_count"),
    myRole: optionalString(value, "my_role"),
    membershipStatus: optionalString(value, "membership_status"),
    updatedAt: optionalString(value, "updated_at"),
  };
}

function isPlainGroup(value: Record<string, unknown>): boolean {
  const required = value.required_security_profile;
  if (
    required !== undefined &&
    required !== null &&
    required !== "transport-protected"
  ) {
    return false;
  }
  const policy = value.group_policy;
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) {
    return true;
  }
  const profile = (policy as Record<string, unknown>).message_security_profile;
  return profile === undefined || profile === "transport-protected";
}

function validateMutationResult(
  method: string,
  params: Record<string, unknown>,
  result: Record<string, unknown>,
): void {
  const meta = asObject(params.meta);
  const groupDid = result.group_did;
  if (typeof groupDid !== "string" || !groupDid) {
    throw new Error(`service returned an invalid ${method} group identifier`);
  }
  positiveInt(result.group_state_version, "group_state_version");
  positiveInt(result.group_event_seq, "group_event_seq");
  if (result.group_receipt === undefined || result.group_receipt === null) {
    return;
  }
  const receipt = asObject(result.group_receipt);
  if (receipt.e2ee !== undefined && receipt.e2ee !== null) {
    throw new Error("ordinary Group receipt contains E2EE material");
  }
  if (
    receipt.subject_method !== method ||
    receipt.group_did !== groupDid ||
    receipt.operation_id !== meta.operation_id
  ) {
    throw new Error("service returned a mismatched Group receipt");
  }
  if (
    meta.message_id !== undefined &&
    meta.message_id !== null &&
    receipt.message_id !== meta.message_id
  ) {
    throw new Error("service returned a mismatched Group message receipt");
  }
  if (receipt.proof !== undefined && receipt.proof !== null) {
    if (typeof receipt.proof !== "object" || Array.isArray(receipt.proof)) {
      throw new Error("service returned an invalid Group receipt proof");
    }
  }
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProtocolResponseError("service returned an invalid Group result");
  }
  return value as Record<string, unknown>;
}

function asMaybeObject(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function requiredList(
  value: Record<string, unknown>,
  field: string,
): unknown[] {
  const result = value[field];
  if (!Array.isArray(result)) {
    throw new Error(`service returned invalid ${field}`);
  }
  return result;
}

function optionalPositiveInt(
  container: Record<string, unknown> | null,
  field: string,
): number | null {
  if (
    !container ||
    container[field] === undefined ||
    container[field] === null
  ) {
    return null;
  }
  return positiveInt(container[field], field);
}

function positiveInt(value: unknown, field: string): number {
  const parsed = parseWireInt(value, field);
  if (parsed <= 0) {
    throw new ProtocolResponseError(`service returned invalid ${field}`);
  }
  return parsed;
}

function nonnegativeInt(value: unknown, field: string): number {
  const parsed = parseWireInt(value, field);
  if (parsed < 0) {
    throw new ProtocolResponseError(`service returned invalid ${field}`);
  }
  return parsed;
}

function parseWireInt(value: unknown, field: string): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return value;
  }
  if (typeof value === "string" && /^0$|^[1-9][0-9]*$/.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed)) {
      return parsed;
    }
  }
  throw new ProtocolResponseError(`service returned invalid ${field}`);
}

function nextCursor(value: Record<string, unknown>): string | null {
  const hasMore = value.has_more;
  if (typeof hasMore !== "boolean") {
    throw new ProtocolResponseError("service returned invalid has_more");
  }
  const cursor = value.next_cursor;
  if (hasMore && (typeof cursor !== "string" || !cursor)) {
    throw new Error("service omitted the next group cursor");
  }
  if (!hasMore && cursor !== undefined && cursor !== null) {
    throw new Error("service returned a cursor for a terminal group page");
  }
  return typeof cursor === "string" ? cursor : null;
}

function optionalTimestamp(value: Record<string, unknown>): string {
  const result =
    value.sent_at !== undefined ? value.sent_at : (value.created_at ?? "");
  if (typeof result !== "string") {
    throw new ProtocolResponseError(
      "service returned invalid message timestamp",
    );
  }
  return result;
}

function responseDid(value: Record<string, unknown>, field: string): string {
  try {
    return validateDid(requiredString(value, field), field);
  } catch (error) {
    if (error instanceof ProtocolResponseError) {
      throw error;
    }
    throw new ProtocolResponseError(`service returned invalid ${field}`);
  }
}
