import { Command } from "commander";

import { RegistrationWorkflow } from "../application/registration.js";
import { generateIdentity } from "../infrastructure/anp-sdk.js";
import { MessageService } from "../infrastructure/message-service.js";
import type { SyncBootstrapState } from "../domain/models.js";
import type { SecureStateStore } from "../infrastructure/state.js";
import { UserService } from "../infrastructure/user-service.js";
import {
  createRuntime,
  promptPassphrase,
  promptText,
  wrapMain,
} from "./runtime.js";

export function registerIdentityCommand(root: Command): void {
  root
    .command("register")
    .description("Register one local AWiki identity.")
    .option("--handle <handle>", "Handle local-part to register.")
    .option("--phone <phone>", "Phone number used for OTP verification.")
    .action((options: { handle?: string; phone?: string }) => {
      wrapMain("registration", async () => {
        console.log(
          "Warning: losing this state directory or passphrase permanently loses the identity.",
        );
        const handle = options.handle ?? (await promptText("Handle"));
        const phone = options.phone ?? (await promptText("Phone"));
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new RegistrationWorkflow(
            new UserService(http.client, settings.userServiceUrl),
            new MessageService(http.client, settings.messageServiceUrl),
            store,
            settings.messageServiceUrl,
            generateIdentity,
          );
          const [canonicalHandle, canonicalPhone, domain, otpRequired] =
            await workflow.begin(handle, phone);
          let otp = "000000";
          if (otpRequired) {
            otp = await promptPassphrase("OTP", false);
          } else {
            console.log(
              "Open Server does not perform phone verification; continuing locally.",
            );
          }
          const passphrase = await promptPassphrase(
            "Local key passphrase",
            true,
          );
          const identity = await workflow.finish(
            canonicalHandle,
            canonicalPhone,
            domain,
            otp,
            passphrase,
          );
          console.log(`Registered ${identity.handle} (${identity.did})`);
        } finally {
          http.close();
        }
      });
    });
  root
    .command("init-sync")
    .description(
      "Explicitly initialize Sync V2 for an identity created by an older Lite version.",
    )
    .action(() => {
      wrapMain("sync", async () => {
        const { settings, store, http } = createRuntime();
        try {
          const identity = store.loadPublic();
          const existing = store.loadSync(identity.did);
          if (existing !== null && existing.bootstrap !== null) {
            console.log(
              `Message sync is already initialized for ${identity.did}`,
            );
            return;
          }
          console.log(
            "Warning: the server may use tail_only; messages from before initialization may remain unavailable.",
          );
          const bootstrap = await initializeMessageSync(
            store,
            new MessageService(http.client, settings.messageServiceUrl),
          );
          console.log(
            `Message sync initialized for ${identity.did} at stream ${bootstrap.streamEpoch}:${bootstrap.scanSeq}`,
          );
        } finally {
          http.close();
        }
      });
    });
}

export async function initializeMessageSync(
  store: SecureStateStore,
  service: MessageService,
): Promise<SyncBootstrapState> {
  const identity = {
    identity: store.loadPublic(),
    session: store.loadSession(),
  };
  const installation = store.initializeSync(identity.identity.did);
  if (installation.bootstrap !== null) {
    return installation.bootstrap;
  }
  const bootstrap = await service.bootstrapSync(
    identity,
    installation.clientInstanceId,
  );
  store.completeSyncBootstrap(installation, bootstrap);
  return bootstrap;
}
