import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const SERVICE_NAME = "com.agentconnect.awiki-lite-listener";
export const SERVICE_DESCRIPTION =
  "Receives authenticated AWiki synchronization notifications.";

export class ListenerServiceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ListenerServiceError";
  }
}

export interface ServiceContext {
  readonly execPath: string;
  readonly scriptPath: string;
  readonly stateDir: string;
  readonly messageServiceUrl: string;
  readonly home: string;
  readonly uid: number | null;
  readonly platform: string;
  readonly caBundle: string | null;
}

export interface ListenerServiceStatus {
  readonly platform: string;
  readonly installed: boolean;
  readonly running: boolean;
  readonly state: string;
}

export interface CommandRunner {
  run(
    command: readonly string[],
    options?: { check?: boolean },
  ): { status: number; stdout: string };
}

export class ProcessCommandRunner implements CommandRunner {
  run(
    command: readonly string[],
    options: { check?: boolean } = {},
  ): { status: number; stdout: string } {
    const [executable, ...args] = command;
    if (!executable) {
      throw new ListenerServiceError(
        "the platform service manager is unavailable",
      );
    }
    let result: {
      error?: Error | undefined;
      status: number | null;
      stdout: string | Buffer | null;
    };
    try {
      result = spawnSync(executable, args, {
        encoding: "utf8",
        timeout: 30_000,
      });
    } catch {
      throw new ListenerServiceError(
        "the platform service manager is unavailable",
      );
    }
    if (result.error || result.status === null) {
      throw new ListenerServiceError(
        "the platform service manager is unavailable",
      );
    }
    if ((options.check ?? true) && result.status !== 0) {
      throw new ListenerServiceError(
        "the platform service manager rejected the operation",
      );
    }
    const stdout = typeof result.stdout === "string" ? result.stdout : "";
    return { status: result.status, stdout };
  }
}

export function currentServiceContext(
  stateDir: string,
  messageServiceUrl: string,
  argv = process.argv,
  options: {
    home?: string;
    platform?: string;
    uid?: number | null;
    caBundle?: string | null;
  } = {},
): ServiceContext {
  const script = argv[1]
    ? realpathSync(argv[1])
    : realpathSync(process.argv[1] ?? process.execPath);
  return {
    execPath: process.execPath,
    scriptPath: script,
    stateDir,
    messageServiceUrl,
    home: options.home ?? homedir(),
    uid:
      options.uid ??
      (typeof process.getuid === "function" ? process.getuid() : null),
    platform: options.platform ?? process.platform,
    caBundle: options.caBundle ?? null,
  };
}

export function serviceCommand(context: ServiceContext): string[] {
  const command = [
    context.execPath,
    context.scriptPath,
    "runtime",
    "listener",
    "run",
    "--service-mode",
    "--state-dir",
    context.stateDir,
    "--message-service-url",
    context.messageServiceUrl,
  ];
  if (context.caBundle) {
    command.push("--ca-bundle", context.caBundle);
  }
  return command;
}

export function unitContents(context: ServiceContext): string {
  const command = serviceCommand(context).map(systemdQuote).join(" ");
  return [
    "[Unit]",
    `Description=${SERVICE_DESCRIPTION}`,
    "After=network-online.target",
    "Wants=network-online.target",
    "",
    "[Service]",
    "Type=simple",
    `ExecStart=${command}`,
    `Environment=AWIKI_LITE_STATE_DIR=${systemdQuote(context.stateDir)}`,
    `Environment=AWIKI_MESSAGE_SERVICE_URL=${systemdQuote(context.messageServiceUrl)}`,
    "Restart=on-failure",
    "RestartSec=1s",
    "",
    "[Install]",
    "WantedBy=default.target",
    "",
  ].join("\n");
}

export function unitPath(context?: Pick<ServiceContext, "home">): string {
  return join(
    context?.home ?? homedir(),
    ".config",
    "systemd",
    "user",
    `${SERVICE_NAME}.service`,
  );
}

export function plistPath(context: Pick<ServiceContext, "home">): string {
  return join(context.home, "Library", "LaunchAgents", `${SERVICE_NAME}.plist`);
}

export abstract class ListenerServiceManager {
  constructor(
    readonly context: ServiceContext,
    protected readonly runner: CommandRunner,
  ) {}

  abstract readonly platform: string;
  abstract status(): ListenerServiceStatus;
  abstract install(): ListenerServiceStatus;
  abstract start(): ListenerServiceStatus;
  abstract stop(): ListenerServiceStatus;
  abstract uninstall(): ListenerServiceStatus;

  restart(): ListenerServiceStatus {
    if (!this.status().installed) {
      throw new ListenerServiceError("listener service is not installed");
    }
    this.stop();
    return this.start();
  }
}

class UnsupportedManager extends ListenerServiceManager {
  readonly platform = "unsupported";

  status(): ListenerServiceStatus {
    throw new ListenerServiceError(
      "listener services are unsupported on this operating system",
    );
  }

  install(): ListenerServiceStatus {
    return this.status();
  }

  start(): ListenerServiceStatus {
    return this.status();
  }

  stop(): ListenerServiceStatus {
    return this.status();
  }

  uninstall(): ListenerServiceStatus {
    return this.status();
  }
}

export class SystemdUserManager extends ListenerServiceManager {
  readonly platform = "linux-systemd-user";

  get unitName(): string {
    return `${SERVICE_NAME}.service`;
  }

  get path(): string {
    return unitPath(this.context);
  }

  status(): ListenerServiceStatus {
    const result = this.runner.run(
      [
        "systemctl",
        "--user",
        "show",
        this.unitName,
        "--property=LoadState",
        "--property=ActiveState",
        "--value",
      ],
      { check: false },
    );
    const lines = result.stdout.split("\n");
    const loadState = (lines[0] ?? "").trim() || "not-found";
    const activeState = (lines[1] ?? "").trim() || "inactive";
    const installed = existsSync(this.path) && loadState !== "not-found";
    const running =
      installed && (activeState === "active" || activeState === "activating");
    return { platform: this.platform, installed, running, state: activeState };
  }

  install(): ListenerServiceStatus {
    mkdirSync(join(this.context.home, ".config", "systemd", "user"), {
      recursive: true,
      mode: 0o700,
    });
    writeFileSync(this.path, unitContents(this.context), { mode: 0o600 });
    this.runner.run(["systemctl", "--user", "daemon-reload"]);
    this.runner.run(["systemctl", "--user", "enable", this.unitName]);
    return this.status();
  }

  start(): ListenerServiceStatus {
    if (!this.status().installed) {
      this.install();
    }
    this.runner.run(["systemctl", "--user", "start", this.unitName]);
    return this.status();
  }

  stop(): ListenerServiceStatus {
    if (this.status().installed) {
      this.runner.run(["systemctl", "--user", "stop", this.unitName]);
    }
    return this.status();
  }

  restart(): ListenerServiceStatus {
    if (!this.status().installed) {
      throw new ListenerServiceError("listener service is not installed");
    }
    this.runner.run(["systemctl", "--user", "restart", this.unitName]);
    return this.status();
  }

  uninstall(): ListenerServiceStatus {
    const current = this.status();
    if (current.installed) {
      if (current.running) {
        this.runner.run(["systemctl", "--user", "stop", this.unitName]);
      }
      this.runner.run(["systemctl", "--user", "disable", this.unitName]);
    }
    if (existsSync(this.path)) {
      rmSync(this.path);
    }
    this.runner.run(["systemctl", "--user", "daemon-reload"]);
    return {
      platform: this.platform,
      installed: false,
      running: false,
      state: "not-installed",
    };
  }
}

export class LaunchAgentManager extends ListenerServiceManager {
  readonly platform = "macos-launchagent";

  get path(): string {
    return plistPath(this.context);
  }

  get target(): string {
    if (this.context.uid === null) {
      throw new ListenerServiceError(
        "the current user identifier is unavailable",
      );
    }
    return `gui/${this.context.uid}/${SERVICE_NAME}`;
  }

  get domain(): string {
    if (this.context.uid === null) {
      throw new ListenerServiceError(
        "the current user identifier is unavailable",
      );
    }
    return `gui/${this.context.uid}`;
  }

  status(): ListenerServiceStatus {
    if (!existsSync(this.path)) {
      return {
        platform: this.platform,
        installed: false,
        running: false,
        state: "not-installed",
      };
    }
    const result = this.runner.run(["launchctl", "print", this.target], {
      check: false,
    });
    const running =
      result.status === 0 &&
      (/(?:^|\n)\s*state\s*=\s*running\s*(?:\n|$)/.test(result.stdout) ||
        /(?:^|\n)\s*pid\s*=\s*[1-9][0-9]*\s*(?:\n|$)/.test(result.stdout));
    const state = running
      ? "running"
      : result.status === 0
        ? "loaded"
        : "unloaded";
    return { platform: this.platform, installed: true, running, state };
  }

  install(): ListenerServiceStatus {
    const logs = join(this.context.stateDir, "logs");
    mkdirSync(logs, { recursive: true, mode: 0o700 });
    mkdirSync(join(this.context.home, "Library", "LaunchAgents"), {
      recursive: true,
      mode: 0o700,
    });
    const argumentsJson = JSON.stringify(serviceCommand(this.context));
    const plist = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
      '<plist version="1.0">',
      "<dict>",
      "<key>Label</key>",
      `<string>${SERVICE_NAME}</string>`,
      "<key>ProgramArguments</key>",
      arrayToPlist(serviceCommand(this.context)),
      "<key>EnvironmentVariables</key>",
      "<dict>",
      "<key>AWIKI_LITE_STATE_DIR</key>",
      `<string>${escapeXml(this.context.stateDir)}</string>`,
      "<key>AWIKI_MESSAGE_SERVICE_URL</key>",
      `<string>${escapeXml(this.context.messageServiceUrl)}</string>`,
      "</dict>",
      "<key>RunAtLoad</key>",
      "<true/>",
      "<key>StandardOutPath</key>",
      `<string>${escapeXml(join(logs, "listener.out.log"))}</string>`,
      "<key>StandardErrorPath</key>",
      `<string>${escapeXml(join(logs, "listener.err.log"))}</string>`,
      "</dict>",
      "</plist>",
      "",
    ].join("\n");
    writeFileSync(this.path, plist, { mode: 0o600 });
    void argumentsJson;
    return this.status();
  }

  start(): ListenerServiceStatus {
    this.install();
    const current = this.status();
    if (current.state === "unloaded") {
      this.runner.run(["launchctl", "bootstrap", this.domain, this.path]);
    } else {
      this.runner.run(["launchctl", "kickstart", "-k", this.target]);
    }
    return this.status();
  }

  stop(): ListenerServiceStatus {
    const current = this.status();
    if (current.installed && current.state !== "unloaded") {
      this.runner.run(["launchctl", "bootout", this.domain, this.path]);
    }
    return this.status();
  }

  uninstall(): ListenerServiceStatus {
    if (this.status().installed) {
      this.stop();
      if (existsSync(this.path)) {
        rmSync(this.path);
      }
    }
    return {
      platform: this.platform,
      installed: false,
      running: false,
      state: "not-installed",
    };
  }
}

export class WindowsTaskManager extends ListenerServiceManager {
  readonly platform = "windows-scheduled-task";
  readonly taskName = String.raw`\AgentConnect\AWikiLiteListener`;

  status(): ListenerServiceStatus {
    const result = this.runner.run(
      ["schtasks.exe", "/Query", "/TN", this.taskName, "/FO", "LIST"],
      { check: false },
    );
    if (result.status !== 0) {
      return {
        platform: this.platform,
        installed: false,
        running: false,
        state: "not-installed",
      };
    }
    const stateResult = this.runner.run(
      [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "(Get-ScheduledTask -TaskName 'AWikiLiteListener' -TaskPath '\\AgentConnect\\').State.ToString()",
      ],
      { check: false },
    );
    const state = stateResult.stdout.trim().toLowerCase() || "unknown";
    return {
      platform: this.platform,
      installed: true,
      running: state === "running",
      state,
    };
  }

  install(): ListenerServiceStatus {
    if (this.status().installed) {
      throw new ListenerServiceError(
        "listener service is already installed; uninstall it first",
      );
    }
    this.runner.run([
      "schtasks.exe",
      "/Create",
      "/TN",
      this.taskName,
      "/TR",
      windowsCommandLine(serviceCommand(this.context)),
      "/SC",
      "ONLOGON",
      "/RL",
      "LIMITED",
      "/IT",
      "/F",
    ]);
    return this.status();
  }

  start(): ListenerServiceStatus {
    if (!this.status().installed) {
      this.install();
    }
    this.runner.run(["schtasks.exe", "/Run", "/TN", this.taskName]);
    return this.status();
  }

  stop(): ListenerServiceStatus {
    const current = this.status();
    if (current.installed && current.running) {
      this.runner.run(["schtasks.exe", "/End", "/TN", this.taskName]);
    }
    return this.status();
  }

  uninstall(): ListenerServiceStatus {
    if (this.status().installed) {
      this.stop();
      this.runner.run(["schtasks.exe", "/Delete", "/TN", this.taskName, "/F"]);
    }
    return {
      platform: this.platform,
      installed: false,
      running: false,
      state: "not-installed",
    };
  }
}

export function windowsCommandLine(values: string[]): string {
  return values.map(windowsQuote).join(" ");
}

function windowsQuote(value: string): string {
  if (value && !/[\s"]/.test(value)) {
    return value;
  }
  let output = '"';
  let backslashes = 0;
  for (const character of value) {
    if (character === "\\") {
      backslashes += 1;
      continue;
    }
    if (character === '"') {
      output += "\\".repeat(backslashes * 2 + 1) + '"';
      backslashes = 0;
      continue;
    }
    output += "\\".repeat(backslashes) + character;
    backslashes = 0;
  }
  return output + "\\".repeat(backslashes * 2) + '"';
}

export function serviceManager(
  context: ServiceContext,
  runner: CommandRunner = new ProcessCommandRunner(),
): ListenerServiceManager {
  if (context.platform.startsWith("linux")) {
    return new SystemdUserManager(context, runner);
  }
  if (context.platform === "darwin") {
    return new LaunchAgentManager(context, runner);
  }
  if (context.platform === "win32" || context.platform === "cygwin") {
    return new WindowsTaskManager(context, runner);
  }
  return new UnsupportedManager(context, runner);
}

export function installListener(
  context: ServiceContext,
  runner?: CommandRunner,
): ListenerServiceStatus {
  return serviceManager(context, runner).install();
}

export function uninstallListener(
  context: ServiceContext,
  runner?: CommandRunner,
): ListenerServiceStatus {
  return serviceManager(context, runner).uninstall();
}

export function listenerStatus(
  context: ServiceContext,
  runner?: CommandRunner,
): ListenerServiceStatus {
  return serviceManager(context, runner).status();
}

export function startListener(
  context: ServiceContext,
  runner?: CommandRunner,
): ListenerServiceStatus {
  return serviceManager(context, runner).start();
}

export function stopListener(
  context: ServiceContext,
  runner?: CommandRunner,
): ListenerServiceStatus {
  return serviceManager(context, runner).stop();
}

export function restartListener(
  context: ServiceContext,
  runner?: CommandRunner,
): ListenerServiceStatus {
  return serviceManager(context, runner).restart();
}

export function installedExecLine(
  context?: Pick<ServiceContext, "home">,
): string | null {
  const path = unitPath(context);
  if (!existsSync(path)) {
    return null;
  }
  const text = readFileSync(path, "utf8");
  const match = text.match(/^ExecStart=(.*)$/m);
  return match?.[1] ?? null;
}

function systemdQuote(value: string): string {
  return `'${value.replace(/'/g, String.raw`'\''`).replace(/%/g, "%%")}'`;
}

function arrayToPlist(values: readonly string[]): string {
  return `<array>\n${values.map((item) => `<string>${escapeXml(item)}</string>`).join("\n")}\n</array>`;
}

function escapeXml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
