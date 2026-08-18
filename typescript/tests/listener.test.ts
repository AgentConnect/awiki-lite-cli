import { chmodSync, existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, test } from 'vitest';
import { WebSocketServer } from 'ws';

import { createProgram } from '../src/cli.js';
import { createRuntime } from '../src/commands/runtime.js';
import { listenerRuntime, runListenerServiceAction } from '../src/commands/listener.js';
import {
  LISTENER_WS_OPTIONS,
  listen,
  SYNC_SUBPROTOCOL,
  websocketUrl,
} from '../src/infrastructure/listener.js';
import {
  currentServiceContext,
  installedExecLine,
  SERVICE_NAME,
  serviceCommand,
  serviceManager,
  unitContents,
  unitPath,
  type CommandRunner,
} from '../src/infrastructure/listener-service.js';
import { DEFAULT_STATE_APPNAME } from '../src/config.js';
import { SecureStateStore } from '../src/infrastructure/state.js';

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'awiki-lsn-'));
}

function seedIdentity(dir: string): void {
  const store = new SecureStateStore(dir);
  store.initialize();
  writeFileSync(
    join(dir, 'identity.json'),
    JSON.stringify({
      did: 'did:wba:example.com:user:alice:e1_alice',
      handle: 'alice.example.com',
      verification_method: 'did:wba:example.com:user:alice:e1_alice#key-1',
      device_id: 'dev-1',
      did_document: { id: 'did:wba:example.com:user:alice:e1_alice' },
    }),
  );
  writeFileSync(join(dir, 'session.json'), JSON.stringify({ access_token: 'tok' }));
  chmodSync(join(dir, 'identity.json'), 0o600);
  chmodSync(join(dir, 'session.json'), 0o600);
}

describe('listener runtime, websocket options, and service actions', () => {
  test('default appname stays isolated', () => {
    expect(DEFAULT_STATE_APPNAME).toBe('awiki-lite-cli-ts');
  });

  test('websocket options match the Python listener table', () => {
    expect(LISTENER_WS_OPTIONS.pingIntervalMs).toBe(60_000);
    expect(LISTENER_WS_OPTIONS.pingTimeoutMs).toBe(15_000);
    expect(LISTENER_WS_OPTIONS.handshakeTimeoutMs).toBe(15_000);
    expect(LISTENER_WS_OPTIONS.closeTimeoutMs).toBe(10_000);
    expect(LISTENER_WS_OPTIONS.maxPayloadBytes).toBe(1024 * 1024);
    expect(LISTENER_WS_OPTIONS.maxQueue).toBe(128);
    expect(LISTENER_WS_OPTIONS.proxy).toBeNull();
    expect(websocketUrl('https://awiki.info')).toBe('wss://awiki.info/im/ws');
  });

  test('--state-dir wins over AWIKI_LITE_STATE_DIR', () => {
    const envDir = tempDir();
    const flagDir = tempDir();
    seedIdentity(flagDir);
    const runtime = listenerRuntime({ stateDir: flagDir });
    expect(runtime.settings.stateDir).toBe(flagDir);
    expect(runtime.store.loadPublic().did).toBe('did:wba:example.com:user:alice:e1_alice');
    const ignored = createRuntime({
      stateDir: flagDir,
      env: { ...process.env, AWIKI_LITE_STATE_DIR: envDir },
    });
    expect(ignored.settings.stateDir).toBe(flagDir);
  });

  test('hidden listener flags exist on the shipped command', () => {
    const run = createProgram()
      .commands.find((command) => command.name() === 'listener')
      ?.commands.find((command) => command.name() === 'run');
    const longs = run?.options.map((option) => option.long) ?? [];
    expect(longs).toContain('--state-dir');
    expect(longs).toContain('--service-mode');
    expect(longs).toContain('--message-service-url');
    const names =
      createProgram()
        .commands.find((command) => command.name() === 'listener')
        ?.commands.map((command) => command.name()) ?? [];
    expect(names).toEqual(expect.arrayContaining(['run', 'install', 'start', 'stop', 'restart', 'status', 'uninstall']));
  });

  test('systemd start/stop/restart invoke the platform manager', () => {
    const home = tempDir();
    const stateDir = tempDir();
    const context = currentServiceContext(stateDir, 'https://awiki.info', process.argv, {
      home,
      platform: 'linux',
    });
    const commands: string[][] = [];
    let started = false;
    const runner: CommandRunner = {
      run(command) {
        commands.push([...command]);
        if (command.includes('show')) {
          if (!existsSync(unitPath(context))) {
            return { status: 0, stdout: 'not-found\ninactive\n' };
          }
          return { status: 0, stdout: started ? 'loaded\nactive\n' : 'loaded\ninactive\n' };
        }
        if (command.includes('start') || command.includes('restart')) {
          started = true;
        }
        if (command.includes('stop')) {
          started = false;
        }
        return { status: 0, stdout: '' };
      },
    };
    const manager = serviceManager(context, runner);
    const startedStatus = manager.start();
    expect(startedStatus.running).toBe(true);
    expect(commands.some((item) => item.includes('start'))).toBe(true);
    expect(installedExecLine(context)).toContain("'listener'");
    expect(installedExecLine(context)).toContain("'run'");
    expect(installedExecLine(context)).toContain("'--service-mode'");
    expect(installedExecLine(context)).toContain("'--state-dir'");
    expect(unitContents(context)).toContain(context.execPath);
    expect(serviceCommand(context)[0]).toBe(process.execPath);
    expect(serviceCommand(context)).toContain('--message-service-url');
    expect(SERVICE_NAME).toBe('com.agentconnect.awiki-lite-listener');
    manager.stop();
    expect(commands.some((item) => item.includes('stop'))).toBe(true);
    manager.start();
    manager.restart();
    expect(commands.some((item) => item.includes('restart'))).toBe(true);
  });

  test('runListenerServiceAction start requires a registered identity', () => {
    const empty = tempDir();
    expect(() =>
      runListenerServiceAction('start', {
        stateDir: empty,
        requireIdentity: true,
      }),
    ).toThrow(/not registered|identity/i);
  });

  test('listen consumes one negotiated sync.changed frame', async () => {
    const server = new WebSocketServer({
      port: 0,
      handleProtocols: () => SYNC_SUBPROTOCOL,
    });
    await new Promise<void>((resolve) => server.once('listening', () => resolve()));
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    server.on('connection', (socket) => {
      expect(socket.protocol).toBe(SYNC_SUBPROTOCOL);
      socket.send(
        JSON.stringify({
          method: 'sync.changed',
          payload: { domains: ['inbox'], reason: 'new-message' },
          sync: { schema_version: 2, account_scan_seq_hint: '3', domain_versions: { inbox: '1' } },
        }),
      );
    });
    try {
      const events: string[] = [];
      await listen(`http://127.0.0.1:${port}`, 'tok', (event) => {
        events.push(event.reason);
      }, { once: true });
      expect(events).toEqual(['new-message']);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
