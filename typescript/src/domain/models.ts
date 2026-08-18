export interface IdentityState {
  readonly did: string;
  readonly handle: string;
  readonly verificationMethod: string;
  readonly deviceId: string;
  readonly didDocument: Record<string, unknown>;
}

export interface SessionState {
  readonly accessToken: string;
}

export interface PendingOperation {
  readonly schemaVersion: number;
  readonly kind: string;
  readonly targetDid: string;
  readonly inputSha256: string;
  readonly operationId: string;
  readonly messageId: string | null;
  readonly createdAt: string;
  readonly proofCreated: number;
  readonly proofNonce: string;
  readonly values: Readonly<Record<string, string>>;
  readonly stage: string | null;
}

export interface PendingSend {
  readonly recipientDid: string;
  readonly contentSha256: string;
  readonly operationId: string;
  readonly messageId: string;
  readonly createdAt: string;
  readonly proofCreated: number;
  readonly proofNonce: string;
}

export interface AuthenticatedIdentity {
  readonly identity: IdentityState;
  readonly session: SessionState;
}

export interface UnlockedIdentity extends AuthenticatedIdentity {
  readonly rootPrivateKeyPem: string;
  readonly deviceSigningPrivateKeyPem: string;
  readonly deviceAgreementPrivateKeyPem: string;
}

export interface AttachmentRef {
  readonly attachmentId: string;
  readonly objectUri: string;
  readonly filename: string;
  readonly mimeType: string;
  readonly size: number;
  readonly sha256B64u: string;
}

export interface AttachmentContext {
  readonly messageId: string;
  readonly senderDid: string;
  readonly messageTargetDid: string | null;
  readonly groupDid: string | null;
  readonly attachment: AttachmentRef;
}

export interface ChatMessage {
  readonly messageId: string;
  readonly senderDid: string;
  readonly targetDid: string;
  readonly text: string;
  readonly createdAt: string | null;
  readonly isRead: boolean | null;
  readonly attachments: readonly AttachmentRef[];
  readonly caption: string | null;
}

export interface GroupSummary {
  readonly groupDid: string;
  readonly displayName: string;
  readonly groupStateVersion: string;
  readonly memberCount: number;
  readonly myRole: string | null;
  readonly membershipStatus: string | null;
  readonly updatedAt: string | null;
}

export interface GroupMember {
  readonly agentDid: string;
  readonly role: string;
  readonly status: string;
}

export interface GroupMessage {
  readonly messageId: string;
  readonly groupDid: string;
  readonly senderDid: string;
  readonly messageType: string;
  readonly content: unknown;
  readonly contentType: string;
  readonly groupEventSeq: number;
  readonly createdAt: string;
}

export function identityEquals(left: IdentityState, right: IdentityState): boolean {
  return (
    left.did === right.did &&
    left.handle === right.handle &&
    left.verificationMethod === right.verificationMethod &&
    left.deviceId === right.deviceId &&
    JSON.stringify(left.didDocument) === JSON.stringify(right.didDocument)
  );
}

export function pendingEquals(left: PendingOperation, right: PendingOperation): boolean {
  return JSON.stringify(pendingToJson(left)) === JSON.stringify(pendingToJson(right));
}

export function pendingToJson(pending: PendingOperation): Record<string, unknown> {
  return {
    schema_version: pending.schemaVersion,
    kind: pending.kind,
    target_did: pending.targetDid,
    input_sha256: pending.inputSha256,
    operation_id: pending.operationId,
    message_id: pending.messageId,
    created_at: pending.createdAt,
    proof_created: pending.proofCreated,
    proof_nonce: pending.proofNonce,
    values: pending.values,
    stage: pending.stage,
  };
}
