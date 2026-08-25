export class JsonRpcFailure extends Error {
  readonly rpcMessage: string;

  constructor(
    public readonly code: number,
    rpcMessage: string,
    public readonly data: unknown = null,
  ) {
    super(`JSON-RPC request failed with code ${code}`);
    this.name = "JsonRpcFailure";
    this.rpcMessage = rpcMessage;
  }
}

export class ProtocolResponseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolResponseError";
  }
}

export class InvalidInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidInputError";
  }
}

export class StateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StateError";
  }
}

export class IdentityExistsError extends StateError {
  constructor(message: string) {
    super(message);
    this.name = "IdentityExistsError";
  }
}

export class IdentityMissingError extends StateError {
  constructor(message: string) {
    super(message);
    this.name = "IdentityMissingError";
  }
}

export class PendingOperationError extends StateError {
  constructor(message: string) {
    super(message);
    this.name = "PendingOperationError";
  }
}

export class InvalidPassphraseError extends StateError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPassphraseError";
  }
}

export class SessionExpiredError extends Error {
  constructor() {
    super("session expired");
    this.name = "SessionExpiredError";
  }
}

export class SyncRecoveryRequiredError extends Error {
  constructor() {
    super(
      "this identity requires full sync recovery, which Lite CLI does not support; use the full AWiki CLI to recover existing history",
    );
    this.name = "SyncRecoveryRequiredError";
  }
}
