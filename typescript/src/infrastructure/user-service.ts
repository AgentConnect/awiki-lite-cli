import { randomUUID } from 'node:crypto';

import { JsonRpcFailure } from '../application/errors.js';
import type { IdentityState } from '../domain/models.js';
import { CLIENT_IDENTIFIER } from '../version.js';
import { signHttpRequest } from './anp-sdk.js';
import {
  callJsonRpc,
  decodeJsonRpcResponse,
  encodeJsonRpcRequest,
  type HttpClient,
} from './rpc.js';

const OTP_REASON = 'email_or_phone_verification_is_not_part_of_open_server_mvp';

export class UserService {
  constructor(
    readonly client: HttpClient,
    readonly baseUrl: string,
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  async sendRegistrationOtp(handle: string, domain: string, phone: string): Promise<boolean> {
    try {
      await callJsonRpc(this.client, `${this.baseUrl}/user-service/v1/handle/rpc`, 'send_otp', {
        phone,
        purpose: 'awiki.identity.register.v1',
        handle,
        domain,
        full_handle: `${handle}.${domain}`,
      });
    } catch (error) {
      if (error instanceof JsonRpcFailure) {
        const data = typeof error.data === 'object' && error.data !== null ? (error.data as Record<string, unknown>) : {};
        if (
          error.code === -32010 &&
          data.feature === 'contact_verification' &&
          data.reason === OTP_REASON
        ) {
          return false;
        }
      }
      throw error;
    }
    return true;
  }

  async register(
    didDocument: Record<string, unknown>,
    handle: string,
    phone: string,
    otpCode: string,
  ): Promise<Record<string, unknown>> {
    return asObject(
      await callJsonRpc(this.client, `${this.baseUrl}/user-service/v1/did-auth/rpc`, 'register', {
        did_document: didDocument,
        handle,
        phone,
        otp_code: otpCode,
      }),
    );
  }

  async refreshSession(identity: IdentityState, signingKeyPem: string): Promise<string> {
    const endpoint = `${this.baseUrl}/user-service/v1/did-auth/rpc`;
    const requestId = randomUUID();
    const body = encodeJsonRpcRequest(requestId, 'get_me', {});
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-AWiki-Client-Version': CLIENT_IDENTIFIER,
    };
    Object.assign(
      headers,
      signHttpRequest(identity.didDocument, endpoint, 'POST', signingKeyPem, headers, body, identity.verificationMethod),
    );
    const result = asObject(
      await decodeJsonRpcResponse(await this.client.post(endpoint, { headers, body }), requestId),
    );
    const token = result.access_token;
    if (typeof token !== 'string' || !token.trim()) {
      throw new Error('DID authentication returned no access token');
    }
    if (result.did !== undefined && result.did !== identity.did) {
      throw new Error('DID authentication returned a mismatched identity');
    }
    return token;
  }
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('service returned an invalid result');
  }
  return value as Record<string, unknown>;
}
