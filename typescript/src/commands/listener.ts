import { basename } from 'node:path';

import { Command, Option } from 'commander';

import { listen, ListenerAuthenticationError, syncChangedToJson, websocketUrl } from '../infrastructure/listener.js';
import {
  currentServiceContext,
  ListenerServiceError,
  type ListenerServiceManager,
  listenerStatus,
  restartListener,
  startListener,
  stopListener,
  installListener,
  uninstallListener,
  type ListenerServiceStatus,
} from '../infrastructure/listener-service.js';
import { createRuntime, wrapMain } from './runtime.js';

export function listenerRuntime(options: { stateDir?: string; messageServiceUrl?: string } = {}) {
  const overrides: { stateDir?: string; messageServiceUrl?: string } = {};
  if (options.stateDir !== undefined) {
    overrides.stateDir = options.stateDir;
  }
  if (options.messageServiceUrl !== undefined) {
    overrides.messageServiceUrl = options.messageServiceUrl;
  }
  return createRuntime(overrides);
}

export function runListenerServiceAction(
  action: 'install' | 'start' | 'stop' | 'restart' | 'status' | 'uninstall',
  options: {
    json?: boolean;
    stateDir?: string;
    messageServiceUrl?: string;
    manager?: ListenerServiceManager;
    requireIdentity?: boolean;
  } = {},
): ListenerServiceStatus {
  const { settings, store } = listenerRuntime({
    ...(options.stateDir !== undefined ? { stateDir: options.stateDir } : {}),
    ...(options.messageServiceUrl !== undefined ? { messageServiceUrl: options.messageServiceUrl } : {}),
  });
  const requireIdentity = options.requireIdentity ?? (action === 'install' || action === 'start' || action === 'restart');
  if (requireIdentity) {
    store.loadPublic();
    store.loadSession();
  }
  const context = currentServiceContext(settings.stateDir, settings.messageServiceUrl);
  if (options.manager) {
    return options.manager[action]();
  }
  switch (action) {
    case 'install':
      return installListener(context);
    case 'start':
      return startListener(context);
    case 'stop':
      return stopListener(context);
    case 'restart':
      return restartListener(context);
    case 'status':
      return listenerStatus(context);
    case 'uninstall':
      return uninstallListener(context);
    default: {
      const _never: never = action;
      throw new ListenerServiceError(`unsupported listener action: ${_never}`);
    }
  }
}

export function registerListenerCommand(root: Command): void {
  const listener = root.command('listener').description('Run the authenticated WebSocket receiving helper.');
  listener
    .command('run')
    .option('--once')
    .option('--json')
    .addOption(new Option('--service-mode').hideHelp())
    .addOption(new Option('--state-dir <dir>').hideHelp())
    .addOption(new Option('--message-service-url <url>').hideHelp())
    .action(
      (options: {
        once?: boolean;
        json?: boolean;
        serviceMode?: boolean;
        stateDir?: string;
        messageServiceUrl?: string;
      }) => {
        wrapMain('listener', async () => {
          const { settings, store } = listenerRuntime({
            ...(options.stateDir !== undefined ? { stateDir: options.stateDir } : {}),
            ...(options.messageServiceUrl !== undefined ? { messageServiceUrl: options.messageServiceUrl } : {}),
          });
          const session = store.loadSession();
          const identity = store.loadPublic();
          if (!options.json) {
            console.error(`Listening for ${identity.did} on ${websocketUrl(settings.messageServiceUrl)}`);
          }
          try {
            await listen(
              settings.messageServiceUrl,
              session.accessToken,
              (event) => {
                if (options.json) {
                  console.log(syncChangedToJson(event));
                } else {
                  const sequence =
                    event.accountScanSeqHint !== null ? ` scan-seq=${event.accountScanSeqHint}` : '';
                  console.log(`Changed domains=${event.domains.join(',')} reason=${event.reason}${sequence}`);
                }
              },
              {
                once: Boolean(options.once),
                onReconnect: (delay) => {
                  console.error(`Connection lost; retrying in ${delay}s.`);
                },
              },
            );
          } catch (error) {
            if (error instanceof ListenerAuthenticationError) {
              const argv0 = basename(process.argv[1] ?? 'awiki-lite-ts');
              console.error(`Listener session expired; run \`${argv0} session refresh\`, then restart it.`);
              if (options.serviceMode) {
                return;
              }
              process.exit(1);
            }
            throw error;
          }
        });
      },
    );

  listener.command('install').action(() => {
    serviceAction('install');
  });
  listener.command('uninstall').action(() => {
    serviceAction('uninstall');
  });
  listener.command('status').option('--json').action((options: { json?: boolean }) => {
    serviceAction('status', options.json);
  });
  listener.command('start').action(() => {
    serviceAction('start');
  });
  listener.command('stop').action(() => {
    serviceAction('stop');
  });
  listener.command('restart').action(() => {
    serviceAction('restart');
  });
}

function serviceAction(
  action: 'install' | 'start' | 'stop' | 'restart' | 'status' | 'uninstall',
  jsonOutput = false,
): void {
  try {
    const status = runListenerServiceAction(action);
    if (action === 'status' && jsonOutput) {
      console.log(JSON.stringify(status));
      return;
    }
    if (action === 'status') {
      console.log(`${status.platform} ${status.state}`);
      return;
    }
    console.log(`Listener ${action} ${status.state}.`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Listener service failed: ${message}`);
    process.exit(1);
  }
}
