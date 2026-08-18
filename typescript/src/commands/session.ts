import { Command } from 'commander';

import { UserService } from '../infrastructure/user-service.js';
import { createRuntime, promptPassphrase, wrapMain } from './runtime.js';

export function registerSessionCommand(root: Command): void {
  const session = root.command('session').description('Recover the bearer session without replacing the identity.');
  session
    .command('refresh')
    .description('Refresh the session using the existing encrypted device signing key.')
    .action(() => {
      wrapMain('session', async () => {
        const passphrase = await promptPassphrase();
        const { settings, store, http } = createRuntime();
        try {
          const identity = store.loadPublic();
          const signing = store.loadDeviceSigningKeyPem(passphrase);
          const token = await new UserService(http.client, settings.userServiceUrl).refreshSession(identity, signing);
          store.saveSession(token);
          console.log(`Session refreshed for ${identity.did}`);
        } finally {
          http.close();
        }
      });
    });
}
