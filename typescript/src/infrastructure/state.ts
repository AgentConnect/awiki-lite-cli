import {
  createHash,
  createPrivateKey,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";

import { flockSync } from "fs-ext";

import {
  IdentityExistsError,
  IdentityMissingError,
  InvalidInputError,
  InvalidPassphraseError,
  PendingOperationError,
  StateError,
} from "../application/errors.js";
import {
  identityEquals,
  pendingEquals,
  pendingToJson,
  type AttachmentContext,
  type IdentityState,
  type PendingOperation,
  type PendingSend,
  type SessionState,
  type SyncBootstrapState,
  type SyncInstallationState,
  type UnlockedIdentity,
} from "../domain/models.js";

export const PENDING_SCHEMA_VERSION = 2;
export const ATTACHMENT_CONTEXT_SCHEMA_VERSION = 1;
export const MAX_ATTACHMENT_CONTEXTS = 500;
export const SYNC_INSTALLATION_SCHEMA_VERSION = 1;

const SECRET_NAMES = [
  "root-key",
  "device-signing",
  "device-agreement",
] as const;
const FORBIDDEN_VALUE_WORDS = [
  "token",
  "secret",
  "password",
  "passphrase",
  "private",
  "proof",
  "header",
];

export interface DeviceKeyMap {
  readonly "root-key": string;
  readonly "device-signing": string;
  readonly "device-agreement": string;
}

export class SecureStateStore {
  readonly secretsDir: string;

  constructor(readonly root: string) {
    this.secretsDir = join(root, "secrets");
  }

  initialize(): void {
    ensureDirectory(this.root);
    ensureDirectory(this.secretsDir);
  }

  get exists(): boolean {
    try {
      return lstatSync(join(this.root, "identity.json")).isFile();
    } catch {
      return false;
    }
  }

  lock<T>(fn: () => T): T {
    this.initialize();
    const path = join(this.root, ".lock");
    rejectUnsafeTarget(path);
    const flags =
      constants.O_RDWR | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0);
    const fd = openSync(path, flags, 0o600);
    try {
      securePath(path, false);
      flockSync(fd, "ex");
      const stat = lstatSync(path);
      if (stat.size === 0) {
        writeSync(fd, Buffer.from([0]));
        fsyncSync(fd);
      }
      return fn();
    } finally {
      try {
        flockSync(fd, "un");
      } catch {
        // unlock best-effort
      }
      closeSync(fd);
    }
  }

  stageRegistration(
    identity: IdentityState,
    privateKeys: DeviceKeyMap,
    passphrase: string,
  ): void {
    validatePassphrase(passphrase);
    this.lock(() => {
      rejectUnsafeTarget(join(this.root, "identity.json"));
      if (this.exists) {
        throw new IdentityExistsError("a local identity already exists");
      }
      if (this.loadPendingIdentityUnlocked() !== null) {
        throw new IdentityExistsError("a registration is already pending");
      }
      for (const name of SECRET_NAMES) {
        const pem = encryptPrivateKeyPem(privateKeys[name], passphrase);
        if (!pem.includes("BEGIN ENCRYPTED PRIVATE KEY")) {
          throw new StateError("private key encryption failed");
        }
        atomicWrite(join(this.secretsDir, `${name}.pem`), Buffer.from(pem));
      }
      atomicJson(
        join(this.root, "pending-registration.json"),
        identityJson(identity),
      );
    });
  }

  finalizeRegistration(identity: IdentityState, accessToken: string): void {
    this.lock(() => {
      if (this.exists) {
        throw new IdentityExistsError("a local identity already exists");
      }
      const pending = this.loadPendingIdentityUnlocked();
      if (pending === null || !identityEquals(pending, identity)) {
        throw new StateError(
          "pending registration does not match the accepted identity",
        );
      }
      atomicJson(join(this.root, "session.json"), {
        access_token: accessToken,
      });
      atomicJson(join(this.root, "identity.json"), identityJson(identity));
      const pendingPath = join(this.root, "pending-registration.json");
      if (existsSync(pendingPath)) {
        unlinkSync(pendingPath);
      }
    });
  }

  loadPublic(): IdentityState {
    return parseIdentity(
      this.readJson(join(this.root, "identity.json")),
      "local identity metadata is invalid",
    );
  }

  loadSession(): SessionState {
    const data = this.readJson(join(this.root, "session.json"));
    const token = data.access_token;
    if (typeof token !== "string" || !token) {
      throw new StateError("local session is invalid");
    }
    return { accessToken: token };
  }

  saveSession(accessToken: string): void {
    if (typeof accessToken !== "string" || !accessToken.trim()) {
      throw new StateError("refreshed session is invalid");
    }
    this.lock(() => {
      if (!this.exists) {
        throw new IdentityMissingError("local identity is not registered");
      }
      atomicJson(join(this.root, "session.json"), {
        access_token: accessToken,
      });
    });
  }

  initializeSync(identityDid: string): SyncInstallationState {
    if (!identityDid.trim()) {
      throw new StateError("sync identity is invalid");
    }
    const path = join(this.root, "sync-installation.json");
    return this.lock(() => {
      const existing = this.loadSyncUnlocked(path);
      if (existing !== null) {
        if (existing.identityDid !== identityDid) {
          throw new StateError("sync installation belongs to another identity");
        }
        return existing;
      }
      const state: SyncInstallationState = {
        identityDid,
        clientInstanceId: `lite-installation-${randomBytes(24).toString("base64url")}`,
        bootstrap: null,
      };
      atomicJson(path, syncInstallationJson(state));
      return state;
    });
  }

  loadSync(identityDid: string): SyncInstallationState | null {
    const state = this.loadSyncUnlocked(
      join(this.root, "sync-installation.json"),
    );
    if (state !== null && state.identityDid !== identityDid) {
      throw new StateError("sync installation belongs to another identity");
    }
    return state;
  }

  completeSyncBootstrap(
    installation: SyncInstallationState,
    bootstrap: SyncBootstrapState,
  ): SyncInstallationState {
    const path = join(this.root, "sync-installation.json");
    return this.lock(() => {
      const current = this.loadSyncUnlocked(path);
      if (
        current === null ||
        current.identityDid !== installation.identityDid ||
        current.clientInstanceId !== installation.clientInstanceId
      ) {
        throw new StateError("sync installation changed unexpectedly");
      }
      const completed: SyncInstallationState = { ...current, bootstrap };
      atomicJson(path, syncInstallationJson(completed));
      return completed;
    });
  }

  loadDeviceSigningKeyPem(passphrase: string): string {
    this.loadPublic();
    return this.loadKeys(passphrase)[1];
  }

  unlock(passphrase: string): UnlockedIdentity {
    const identity = this.loadPublic();
    const session = this.loadSession();
    const keys = this.loadKeys(passphrase);
    return {
      identity,
      session,
      rootPrivateKeyPem: keys[0],
      deviceSigningPrivateKeyPem: keys[1],
      deviceAgreementPrivateKeyPem: keys[2],
    };
  }

  loadPendingIdentity(): IdentityState | null {
    return this.loadPendingIdentityUnlocked();
  }

  unlockPendingKeys(passphrase: string): [string, string, string] {
    if (this.loadPendingIdentity() === null) {
      throw new IdentityMissingError("no pending registration exists");
    }
    return this.loadKeys(passphrase);
  }

  prepareSend(recipientDid: string, text: string): PendingSend {
    const contentSha256 = createHash("sha256")
      .update(text, "utf8")
      .digest("hex");
    const operation = this.prepareOperation(
      "direct.send",
      recipientDid,
      contentSha256,
      {
        needsMessageId: true,
      },
    );
    if (operation.messageId === null) {
      throw new StateError("pending operation state is invalid");
    }
    return {
      recipientDid: operation.targetDid,
      contentSha256: operation.inputSha256,
      operationId: operation.operationId,
      messageId: operation.messageId,
      createdAt: operation.createdAt,
      proofCreated: operation.proofCreated,
      proofNonce: operation.proofNonce,
    };
  }

  prepareOperation(
    kind: string,
    targetDid: string,
    inputSha256: string,
    options: {
      needsMessageId: boolean;
      values?: Readonly<Record<string, string>>;
      initialStage?: string | null;
    },
  ): PendingOperation {
    const normalizedValues = { ...(options.values ?? {}) };
    validatePendingInput(kind, targetDid, inputSha256, normalizedValues);
    const initialStage = options.initialStage ?? null;
    if (initialStage !== null && initialStage !== "prepared") {
      throw new StateError("pending operation initial stage is invalid");
    }
    const path = join(this.root, "pending-send.json");
    return this.lock(() => {
      if (existsSync(path) || isSymlink(path)) {
        const pending = parsePendingOperation(this.readJson(path));
        if (
          pending.kind !== kind ||
          pending.targetDid !== targetDid ||
          pending.inputSha256 !== inputSha256 ||
          JSON.stringify(pending.values) !== JSON.stringify(normalizedValues) ||
          (pending.messageId !== null) !== options.needsMessageId ||
          (initialStage === null) !== (pending.stage === null)
        ) {
          throw new PendingOperationError(
            "another operation has an unknown result; retry the exact same command (pending-send.json)",
          );
        }
        return pending;
      }
      const pending: PendingOperation = {
        schemaVersion: PENDING_SCHEMA_VERSION,
        kind,
        targetDid,
        inputSha256,
        operationId: randomUUID(),
        messageId: options.needsMessageId ? randomUUID() : null,
        createdAt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
        proofCreated: Math.floor(Date.now() / 1000),
        proofNonce: randomBytes(9).toString("base64url"),
        values: normalizedValues,
        stage: initialStage,
      };
      atomicJson(path, pendingToJson(pending));
      return pending;
    });
  }

  completeOperation(pending: PendingOperation): void {
    const path = join(this.root, "pending-send.json");
    this.lock(() => {
      const current = parsePendingOperation(this.readJson(path));
      if (!pendingEquals(current, pending)) {
        throw new PendingOperationError(
          "pending send state changed unexpectedly",
        );
      }
      unlinkSync(path);
    });
  }

  abandonOperation(pending: PendingOperation): void {
    const path = join(this.root, "pending-send.json");
    this.lock(() => {
      if (!existsSync(path) && !isSymlink(path)) {
        return;
      }
      const current = parsePendingOperation(this.readJson(path));
      if (pendingEquals(current, pending)) {
        unlinkSync(path);
      }
    });
  }

  advanceOperation(
    pending: PendingOperation,
    nextStage: string,
  ): PendingOperation {
    const transitions: Record<string, string> = {
      prepared: "uploaded",
      uploaded: "committed",
    };
    if (pending.stage === null || transitions[pending.stage] !== nextStage) {
      throw new PendingOperationError(
        "pending operation stage transition is invalid",
      );
    }
    const path = join(this.root, "pending-send.json");
    return this.lock(() => {
      const current = parsePendingOperation(this.readJson(path));
      if (!pendingEquals(current, pending)) {
        throw new PendingOperationError(
          "pending operation state changed unexpectedly",
        );
      }
      const advanced: PendingOperation = { ...pending, stage: nextStage };
      atomicJson(path, pendingToJson(advanced));
      return advanced;
    });
  }

  saveAttachmentContexts(contexts: AttachmentContext[]): void {
    if (contexts.length === 0) {
      return;
    }
    for (const context of contexts) {
      validateAttachmentContext(context);
    }
    const path = join(this.root, "attachment-contexts.json");
    this.lock(() => {
      const existing = this.loadAttachmentContextsUnlocked(path);
      const merged = new Map<string, AttachmentContext>();
      for (const item of existing) {
        merged.set(`${item.messageId}\0${item.attachment.attachmentId}`, item);
      }
      for (const context of contexts) {
        merged.set(
          `${context.messageId}\0${context.attachment.attachmentId}`,
          context,
        );
      }
      const retained = [...merged.values()].slice(-MAX_ATTACHMENT_CONTEXTS);
      atomicJson(path, {
        schema_version: ATTACHMENT_CONTEXT_SCHEMA_VERSION,
        contexts: retained.map(attachmentContextJson),
      });
    });
  }

  loadAttachmentContext(
    messageId: string,
    attachmentId: string,
  ): AttachmentContext {
    const path = join(this.root, "attachment-contexts.json");
    return this.lock(() => {
      const items = this.loadAttachmentContextsUnlocked(path);
      for (let index = items.length - 1; index >= 0; index -= 1) {
        const context = items[index];
        if (
          context &&
          context.messageId === messageId &&
          context.attachment.attachmentId === attachmentId
        ) {
          return context;
        }
      }
      throw new StateError(
        "attachment context is unavailable; refresh the corresponding messages",
      );
    });
  }

  private loadPendingIdentityUnlocked(): IdentityState | null {
    const path = join(this.root, "pending-registration.json");
    if (!existsSync(path) && !isSymlink(path)) {
      return null;
    }
    return parseIdentity(
      this.readJson(path),
      "pending registration is invalid",
    );
  }

  private loadKeys(passphrase: string): [string, string, string] {
    validatePassphrase(passphrase);
    try {
      return SECRET_NAMES.map((name) =>
        decryptPrivateKeyPem(
          this.readRegular(join(this.secretsDir, `${name}.pem`)),
          passphrase,
        ),
      ) as [string, string, string];
    } catch (error) {
      if (
        error instanceof IdentityMissingError ||
        error instanceof StateError
      ) {
        throw error;
      }
      throw new InvalidPassphraseError("unable to unlock identity");
    }
  }

  private loadAttachmentContextsUnlocked(path: string): AttachmentContext[] {
    if (!existsSync(path) && !isSymlink(path)) {
      return [];
    }
    const data = this.readJson(path);
    if (data.schema_version !== ATTACHMENT_CONTEXT_SCHEMA_VERSION) {
      throw new StateError("attachment context schema is unsupported");
    }
    const raw = data.contexts;
    if (!Array.isArray(raw) || raw.length > MAX_ATTACHMENT_CONTEXTS) {
      throw new StateError("attachment context index is invalid");
    }
    return raw.map(parseAttachmentContext);
  }

  private loadSyncUnlocked(path: string): SyncInstallationState | null {
    if (!existsSync(path) && !isSymlink(path)) {
      return null;
    }
    return parseSyncInstallation(this.readJson(path));
  }

  private readRegular(path: string): Buffer {
    try {
      const info = lstatSync(path);
      if (info.isSymbolicLink() || !info.isFile()) {
        throw new StateError("state file is unsafe");
      }
      if (process.platform !== "win32" && (info.mode & 0o077) !== 0) {
        throw new StateError("state file permissions are unsafe");
      }
      return readFileSync(path);
    } catch (error) {
      if (error instanceof StateError) {
        throw error;
      }
      throw new IdentityMissingError("local identity is not registered");
    }
  }

  private readJson(path: string): Record<string, unknown> {
    try {
      const value: unknown = JSON.parse(
        this.readRegular(path).toString("utf8"),
      );
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new StateError("local state file is invalid");
      }
      return value as Record<string, unknown>;
    } catch (error) {
      if (
        error instanceof StateError ||
        error instanceof IdentityMissingError
      ) {
        throw error;
      }
      throw new StateError("local state file is invalid");
    }
  }
}

export function validatePassphrase(passphrase: string): void {
  if (passphrase.length < 12 || !passphrase.trim()) {
    throw new InvalidInputError(
      "passphrase must contain at least 12 characters",
    );
  }
}

export function encryptPrivateKeyPem(
  unencryptedPem: string,
  passphrase: string,
): string {
  const key = createPrivateKey(unencryptedPem);
  const exported = key.export({
    type: "pkcs8",
    format: "pem",
    cipher: "aes-256-cbc",
    passphrase,
  });
  return typeof exported === "string" ? exported : exported.toString();
}

export function decryptPrivateKeyPem(
  pem: Buffer | string,
  passphrase: string,
): string {
  const key = createPrivateKey({ key: pem, format: "pem", passphrase });
  const exported = key.export({ type: "pkcs8", format: "pem" });
  return typeof exported === "string" ? exported : exported.toString();
}

function identityJson(identity: IdentityState): Record<string, unknown> {
  return {
    did: identity.did,
    handle: identity.handle,
    verification_method: identity.verificationMethod,
    device_id: identity.deviceId,
    did_document: identity.didDocument,
  };
}

function parseIdentity(
  data: Record<string, unknown>,
  message: string,
): IdentityState {
  try {
    const document = data.did_document;
    if (
      typeof document !== "object" ||
      document === null ||
      Array.isArray(document)
    ) {
      throw new TypeError("document");
    }
    return {
      did: String(data.did),
      handle: String(data.handle),
      verificationMethod: String(data.verification_method),
      deviceId: String(data.device_id),
      didDocument: document as Record<string, unknown>,
    };
  } catch {
    throw new StateError(message);
  }
}

function parseSyncInstallation(
  data: Record<string, unknown>,
): SyncInstallationState {
  if (data.schema_version !== SYNC_INSTALLATION_SCHEMA_VERSION) {
    throw new StateError("sync installation schema is unsupported");
  }
  try {
    const identityDid = data.identity_did;
    const clientInstanceId = data.client_instance_id;
    if (
      typeof identityDid !== "string" ||
      !identityDid ||
      typeof clientInstanceId !== "string" ||
      !clientInstanceId
    ) {
      throw new TypeError("identity");
    }
    let bootstrap: SyncBootstrapState | null = null;
    if (data.bootstrap !== null && data.bootstrap !== undefined) {
      if (typeof data.bootstrap !== "object" || Array.isArray(data.bootstrap)) {
        throw new TypeError("bootstrap");
      }
      const raw = data.bootstrap as Record<string, unknown>;
      const values = [
        raw.account_id,
        raw.device_id,
        raw.server_time,
        raw.stream_epoch,
        raw.scan_seq,
      ];
      if (values.some((value) => typeof value !== "string" || !value)) {
        throw new TypeError("bootstrap");
      }
      const streamEpoch = String(raw.stream_epoch);
      const scanSeq = String(raw.scan_seq);
      if (
        !/^[0-9]+$/.test(streamEpoch) ||
        BigInt(streamEpoch) < 1n ||
        !/^[0-9]+$/.test(scanSeq)
      ) {
        throw new TypeError("cursor");
      }
      bootstrap = {
        accountId: String(raw.account_id),
        deviceId: String(raw.device_id),
        serverTime: String(raw.server_time),
        streamEpoch,
        scanSeq,
      };
    }
    return { identityDid, clientInstanceId, bootstrap };
  } catch (error) {
    if (error instanceof StateError) {
      throw error;
    }
    throw new StateError("sync installation state is invalid");
  }
}

function syncInstallationJson(
  state: SyncInstallationState,
): Record<string, unknown> {
  return {
    schema_version: SYNC_INSTALLATION_SCHEMA_VERSION,
    identity_did: state.identityDid,
    client_instance_id: state.clientInstanceId,
    bootstrap:
      state.bootstrap === null
        ? null
        : {
            account_id: state.bootstrap.accountId,
            device_id: state.bootstrap.deviceId,
            server_time: state.bootstrap.serverTime,
            stream_epoch: state.bootstrap.streamEpoch,
            scan_seq: state.bootstrap.scanSeq,
          },
  };
}

export function parsePendingOperation(
  data: Record<string, unknown>,
): PendingOperation {
  if (data.schema_version === undefined) {
    return parseLegacyPendingSend(data);
  }
  if (data.schema_version !== PENDING_SCHEMA_VERSION) {
    throw new StateError("pending operation schema is unsupported");
  }
  try {
    const rawValues = data.values ?? {};
    if (
      typeof rawValues !== "object" ||
      rawValues === null ||
      Array.isArray(rawValues) ||
      Object.entries(rawValues).some(([, value]) => typeof value !== "string")
    ) {
      throw new TypeError("values");
    }
    const values = rawValues as Record<string, string>;
    const rawMessageId = data.message_id;
    const pending: PendingOperation = {
      schemaVersion: PENDING_SCHEMA_VERSION,
      kind: String(data.kind),
      targetDid: String(data.target_did),
      inputSha256: String(data.input_sha256),
      operationId: String(data.operation_id),
      messageId:
        rawMessageId === null || rawMessageId === undefined
          ? null
          : String(rawMessageId),
      createdAt: String(data.created_at),
      proofCreated: Number(data.proof_created),
      proofNonce: String(data.proof_nonce),
      values,
      stage:
        data.stage === null || data.stage === undefined
          ? null
          : String(data.stage),
    };
    validatePendingInput(
      pending.kind,
      pending.targetDid,
      pending.inputSha256,
      pending.values,
    );
    if (
      !pending.operationId ||
      !pending.createdAt ||
      pending.proofCreated <= 0 ||
      !Number.isSafeInteger(pending.proofCreated) ||
      !pending.proofNonce
    ) {
      throw new StateError("pending operation state is invalid");
    }
    if (pending.messageId !== null && !pending.messageId) {
      throw new StateError("pending operation state is invalid");
    }
    if (
      pending.stage !== null &&
      !["prepared", "uploaded", "committed"].includes(pending.stage)
    ) {
      throw new StateError("pending operation stage is invalid");
    }
    return pending;
  } catch (error) {
    if (error instanceof StateError) {
      throw error;
    }
    throw new StateError("pending operation state is invalid");
  }
}

function parseLegacyPendingSend(
  data: Record<string, unknown>,
): PendingOperation {
  try {
    const pending: PendingOperation = {
      schemaVersion: PENDING_SCHEMA_VERSION,
      kind: "direct.send",
      targetDid: String(data.recipient_did),
      inputSha256: String(data.content_sha256),
      operationId: String(data.operation_id),
      messageId: String(data.message_id),
      createdAt: String(data.created_at),
      proofCreated: Number(data.proof_created),
      proofNonce: String(data.proof_nonce),
      values: {},
      stage: null,
    };
    validatePendingInput(
      pending.kind,
      pending.targetDid,
      pending.inputSha256,
      pending.values,
    );
    if (
      !pending.operationId ||
      !pending.messageId ||
      !pending.createdAt ||
      pending.proofCreated <= 0 ||
      !Number.isSafeInteger(pending.proofCreated) ||
      !pending.proofNonce
    ) {
      throw new StateError("legacy pending send state is invalid");
    }
    return pending;
  } catch (error) {
    if (error instanceof StateError) {
      throw error;
    }
    throw new StateError("legacy pending send state is invalid");
  }
}

export function validatePendingInput(
  kind: string,
  targetDid: string,
  inputSha256: string,
  values: Readonly<Record<string, string>>,
): void {
  if (
    !kind ||
    !targetDid ||
    inputSha256.length !== 64 ||
    !/^[0-9a-fA-F]+$/.test(inputSha256)
  ) {
    throw new StateError("pending operation input is invalid");
  }
  for (const [key, value] of Object.entries(values)) {
    if (
      !key ||
      !value ||
      key.length > 64 ||
      value.length > 512 ||
      FORBIDDEN_VALUE_WORDS.some((word) => key.toLowerCase().includes(word))
    ) {
      throw new StateError("pending operation values are unsafe");
    }
  }
}

function parseAttachmentContext(value: unknown): AttachmentContext {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new StateError("attachment context index is invalid");
  }
  const record = value as Record<string, unknown>;
  const attachment = record.attachment;
  if (
    typeof attachment !== "object" ||
    attachment === null ||
    Array.isArray(attachment)
  ) {
    throw new StateError("attachment context index is invalid");
  }
  const item = attachment as Record<string, unknown>;
  try {
    const context: AttachmentContext = {
      messageId: String(record.message_id),
      senderDid: String(record.sender_did),
      messageTargetDid:
        record.message_target_did === null ||
        record.message_target_did === undefined
          ? null
          : String(record.message_target_did),
      groupDid:
        record.group_did === null || record.group_did === undefined
          ? null
          : String(record.group_did),
      attachment: {
        attachmentId: String(item.attachment_id),
        objectUri: String(item.object_uri),
        filename: String(item.filename),
        mimeType: String(item.mime_type),
        size: Number(item.size),
        sha256B64u: String(item.sha256_b64u),
      },
    };
    validateAttachmentContext(context);
    return context;
  } catch (error) {
    if (error instanceof StateError) {
      throw error;
    }
    throw new StateError("attachment context index is invalid");
  }
}

function attachmentContextJson(
  context: AttachmentContext,
): Record<string, unknown> {
  return {
    message_id: context.messageId,
    sender_did: context.senderDid,
    message_target_did: context.messageTargetDid,
    group_did: context.groupDid,
    attachment: {
      attachment_id: context.attachment.attachmentId,
      object_uri: context.attachment.objectUri,
      filename: context.attachment.filename,
      mime_type: context.attachment.mimeType,
      size: context.attachment.size,
      sha256_b64u: context.attachment.sha256B64u,
    },
  };
}

function validateAttachmentContext(context: AttachmentContext): void {
  const attachment = context.attachment;
  if (
    !context.messageId ||
    !context.senderDid ||
    (context.messageTargetDid === null) === (context.groupDid === null) ||
    !attachment.attachmentId ||
    !attachment.objectUri.startsWith("https://") ||
    !attachment.filename ||
    !attachment.mimeType ||
    !Number.isSafeInteger(attachment.size) ||
    attachment.size < 0 ||
    !attachment.sha256B64u
  ) {
    throw new StateError("attachment context is invalid");
  }
}

function ensureDirectory(path: string): void {
  if (existsSync(path)) {
    const info = lstatSync(path);
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new StateError("state path is not a safe directory");
    }
    securePath(path, true);
    return;
  }
  mkdirSync(path, { recursive: true, mode: 0o700 });
  securePath(path, true);
}

function rejectUnsafeTarget(path: string): void {
  if (existsSync(path) || isSymlink(path)) {
    const info = lstatSync(path);
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new StateError("state file target is unsafe");
    }
  }
}

function isSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function atomicJson(path: string, value: Record<string, unknown>): void {
  atomicWrite(path, Buffer.from(`${JSON.stringify(value)}\n`));
}

function atomicWrite(path: string, content: Buffer): void {
  rejectUnsafeTarget(path);
  const temporary = join(dirname(path), `.${randomUUID()}.${Date.now()}`);
  let fd: number | null = null;
  try {
    fd = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      0o600,
    );
    securePath(temporary, false);
    try {
      let offset = 0;
      while (offset < content.length) {
        offset += writeSync(fd, content, offset);
      }
      fsyncSync(fd);
    } finally {
      closeSync(fd);
      fd = null;
    }
    renameSync(temporary, path);
    securePath(path, false);
  } catch (error) {
    if (fd !== null) {
      closeSync(fd);
    }
    try {
      unlinkSync(temporary);
    } catch {
      // ignore
    }
    throw error;
  }
}

let cachedWindowsUserSid: string | null = null;

function securePath(path: string, directory: boolean): void {
  if (process.platform !== "win32") {
    chmodSync(path, directory ? 0o700 : 0o600);
    return;
  }
  const userSid = windowsUserSid();
  const permission = directory ? "(OI)(CI)F" : "F";
  const result = spawnSync(
    "icacls.exe",
    [
      path,
      "/inheritance:r",
      "/grant:r",
      `*${userSid}:${permission}`,
      `*S-1-5-18:${permission}`,
    ],
    { encoding: "utf8", windowsHide: true },
  );
  if (result.status !== 0) {
    throw new StateError("unable to protect local state with a Windows ACL");
  }
}

function windowsUserSid(): string {
  if (cachedWindowsUserSid !== null) {
    return cachedWindowsUserSid;
  }
  const result = spawnSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], {
    encoding: "utf8",
    windowsHide: true,
  });
  const match =
    result.status === 0 ? result.stdout.match(/S-\d(?:-\d+)+/) : null;
  if (!match) {
    throw new StateError("unable to determine the current Windows user SID");
  }
  cachedWindowsUserSid = match[0];
  return cachedWindowsUserSid;
}

export function operationFromSend(pending: PendingSend): PendingOperation {
  return {
    schemaVersion: PENDING_SCHEMA_VERSION,
    kind: "direct.send",
    targetDid: pending.recipientDid,
    inputSha256: pending.contentSha256,
    operationId: pending.operationId,
    messageId: pending.messageId,
    createdAt: pending.createdAt,
    proofCreated: pending.proofCreated,
    proofNonce: pending.proofNonce,
    values: {},
    stage: null,
  };
}
