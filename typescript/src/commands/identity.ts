import { Command } from 'commander';

import { RegistrationWorkflow } from '../application/registration.js';
import { generateIdentity } from '../infrastructure/anp-sdk.js';
import { UserService } from '../infrastructure/user-service.js';
import { createRuntime, promptPassphrase, wrapMain } from './runtime.js';

export function registerIdentityCommand(root: Command): void {
  root
    .command('register')
    .description('Register one local AWiki identity.')
    .option('--handle <handle>', 'Handle local-part to register.')
    .option('--phone <phone>', 'Phone number used for OTP verification.')
    .action((options: { handle?: string; phone?: string }) => {
      wrapMain('registration', async () => {
        console.log('Warning: losing this state directory or passphrase permanently loses the identity.');
        const handle = options.handle ?? (await promptText('Handle'));
        const phone = options.phone ?? (await promptText('Phone'));
        const { settings, store, http } = createRuntime();
        try {
          const workflow = new RegistrationWorkflow(
            new UserService(http.client, settings.userServiceUrl),
            store,
            settings.messageServiceUrl,
            generateIdentity,
          );
          const [canonicalHandle, canonicalPhone, domain, otpRequired] = await workflow.begin(handle, phone);
          let otp = '000000';
          if (otpRequired) {
            otp = await promptPassphrase('OTP', false);
          } else {
            console.log('Open Server does not perform phone verification; continuing locally.');
          }
          const passphrase = await promptPassphrase('Local key passphrase', true);
          const identity = await workflow.finish(canonicalHandle, canonicalPhone, domain, otp, passphrase);
          console.log(`Registered ${identity.handle} (${identity.did})`);
        } finally {
          http.close();
        }
      });
    });
}

async function promptText(message: string): Promise<string> {
  const { createInterface } = await import('node:readline/promises');
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(`${message}: `)).trim();
  } finally {
    rl.close();
  }
}
