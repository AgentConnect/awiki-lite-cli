import { URL } from "node:url";

import { InvalidInputError } from "./errors.js";
import type { IdentityState } from "../domain/models.js";
import type { UserService } from "../infrastructure/user-service.js";
import type { MessageService } from "../infrastructure/message-service.js";
import type {
  DeviceKeyMap,
  SecureStateStore,
} from "../infrastructure/state.js";
import type { GeneratedIdentity } from "../infrastructure/anp-sdk.js";

export const HANDLE_RE = /^[a-z][a-z0-9_-]{2,31}$/;

export function normalizeHandle(value: string): string {
  const handle = value.trim().replace(/^@/, "").toLowerCase();
  if (!HANDLE_RE.test(handle)) {
    throw new InvalidInputError(
      "handle must be 3-32 lowercase letters, digits, '_' or '-'",
    );
  }
  return handle;
}

export function normalizePhone(value: string): string {
  const phone = value.trim().replace(/ /g, "");
  if (!/^\+?[0-9]{7,20}$/.test(phone)) {
    throw new InvalidInputError(
      "phone must contain 7-20 digits with an optional leading '+'",
    );
  }
  return phone;
}

export function registrationDomain(userServiceUrl: string): string {
  let hostname: string | null = null;
  try {
    hostname = new URL(userServiceUrl.replace(/\/+$/, "")).hostname;
  } catch {
    hostname = null;
  }
  if (!hostname) {
    throw new InvalidInputError("User Service URL has no hostname");
  }
  return hostname;
}

export class RegistrationWorkflow {
  constructor(
    private readonly service: UserService,
    private readonly syncService: MessageService,
    private readonly store: SecureStateStore,
    private readonly messageUrl: string,
    private readonly identityGenerator: (
      hostname: string,
      handle: string,
      messageUrl: string,
    ) => GeneratedIdentity,
  ) {}

  async begin(
    handleInput: string,
    phoneInput: string,
  ): Promise<[string, string, string, boolean]> {
    if (this.store.exists) {
      throw new Error("a local identity already exists");
    }
    const handle = normalizeHandle(handleInput);
    const phone = normalizePhone(phoneInput);
    const domain = registrationDomain(this.service.baseUrl);
    const validation = await this.service.validateHandle(handle, domain);
    if (validation.available !== true) {
      throw new InvalidInputError(
        String(validation.message ?? "handle is unavailable"),
      );
    }
    const required = await this.service.sendRegistrationOtp(
      handle,
      domain,
      phone,
    );
    return [handle, phone, domain, required];
  }

  async finish(
    handle: string,
    phone: string,
    domain: string,
    otpCode: string,
    passphrase: string,
  ): Promise<IdentityState> {
    if (!/^[0-9]{4,10}$/.test(otpCode.trim())) {
      throw new InvalidInputError("OTP must contain 4-10 digits");
    }
    const expectedHandle = `${handle}.${domain}`;
    const pending = this.store.loadPendingIdentity();
    let identity: IdentityState;
    if (pending !== null && pending.handle === expectedHandle) {
      identity = pending;
      this.store.unlockPendingKeys(passphrase);
    } else {
      const generated = this.identityGenerator(domain, handle, this.messageUrl);
      identity = {
        did: generated.did,
        handle: expectedHandle,
        verificationMethod: generated.deviceSigningKeyId,
        deviceId: generated.deviceId,
        didDocument: generated.didDocument,
      };
      const keys: DeviceKeyMap = {
        "root-key": generated.rootPrivateKeyPem,
        "device-signing": generated.deviceSigningPrivateKeyPem,
        "device-agreement": generated.deviceAgreementPrivateKeyPem,
      };
      this.store.stageRegistration(identity, keys, passphrase);
    }
    const result = await this.service.register(
      identity.didDocument,
      handle,
      phone,
      otpCode.trim(),
    );
    if (result.state !== "registered" || result.did !== identity.did) {
      throw new Error("registration returned an unexpected identity state");
    }
    const token = result.access_token;
    if (typeof token !== "string" || !token) {
      throw new Error("registration did not return a device access token");
    }
    this.store.finalizeRegistration(identity, token);
    try {
      const installation = this.store.initializeSync(identity.did);
      if (installation.bootstrap === null) {
        const bootstrap = await this.syncService.bootstrapSync(
          { identity, session: { accessToken: token } },
          installation.clientInstanceId,
        );
        this.store.completeSyncBootstrap(installation, bootstrap);
      } else if (installation.bootstrap.deviceId !== identity.deviceId) {
        throw new Error("sync installation belongs to another device");
      }
    } catch (error) {
      throw new Error(
        "identity was registered locally, but message sync initialization failed; run id init-sync",
        { cause: error },
      );
    }
    return identity;
  }
}
