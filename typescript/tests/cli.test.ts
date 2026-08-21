import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";
import type { Command } from "commander";

import { createProgram } from "../src/cli.js";
import { CLIENT_IDENTIFIER, VERSION_LABEL } from "../src/version.js";

const here = dirname(fileURLToPath(import.meta.url));
const cliSource = join(here, "../src/cli.ts");
const contract = JSON.parse(
  readFileSync(
    join(here, "../../tests/fixtures/cli-command-contract.json"),
    "utf8",
  ),
) as {
  tree: Record<string, string[]>;
  options: Record<string, string[]>;
};

function commandAt(program: Command, path: string): Command {
  let current = program;
  for (const part of path.split(" ").filter(Boolean)) {
    const next = current.commands.find((item) => item.name() === part);
    if (!next) {
      throw new Error(`missing command: ${path}`);
    }
    current = next;
  }
  return current;
}

function runCli(args: string[]): {
  stdout: string;
  stderr: string;
  status: number | null;
} {
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", cliSource, ...args],
    {
      encoding: "utf8",
      env: { ...process.env },
    },
  );
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    status: result.status,
  };
}

describe("awiki-lite-ts help", () => {
  test.runIf(process.platform === "win32")(
    "installs a Windows command shim without a symbolic-link requirement",
    () => {
      expect(
        existsSync(join(here, "../node_modules/.bin/awiki-lite-ts.cmd")),
      ).toBe(true);
    },
  );
  test("root help lists implemented commands twice consistently", () => {
    const first = runCli(["--help"]);
    const second = runCli(["--help"]);
    expect(first.status).toBe(0);
    expect(second.status).toBe(0);
    expect(first.stdout).toBe(second.stdout);
    for (const name of ["id", "msg", "group", "runtime"]) {
      expect(first.stdout).toContain(name);
    }
    for (const name of [
      "register",
      "session",
      "dm",
      "attachment",
      "listener",
    ]) {
      expect(first.stdout).not.toMatch(
        new RegExp(`^\\s+${name}(?:\\s|$)`, "m"),
      );
    }
  });

  test("version is the TypeScript label", () => {
    const first = runCli(["--version"]);
    const second = runCli(["--version"]);
    expect(first.stdout.trim()).toBe(VERSION_LABEL);
    expect(first.stdout).toBe(second.stdout);
    expect(first.stdout.trim()).not.toBe("0.2.0");
  });

  test("command help exposes contracted flags", () => {
    const send = runCli(["msg", "send", "--help"]);
    for (const flag of ["--to", "--group", "--text", "--file"]) {
      expect(send.stdout).toContain(flag);
    }
    const download = runCli(["msg", "attachment", "download", "--help"]);
    for (const flag of ["--message-id", "--attachment-id", "--output"]) {
      expect(download.stdout).toContain(flag);
    }
    expect(runCli(["id", "--help"]).stdout).toContain("refresh-token");
    expect(runCli(["group", "--help"]).stdout).toContain("get");
    expect(runCli(["runtime", "listener", "--help"]).stdout).toContain(
      "status",
    );
    expect(createProgram().name()).toBe("awiki-lite-ts");
    expect(CLIENT_IDENTIFIER).toBe("awiki-cli/0714/0.2.0");
  });

  test("command tree matches the Python public hierarchy", () => {
    const program = createProgram();
    const help = program.createHelp();
    for (const [path, expected] of Object.entries(contract.tree)) {
      const actual = help
        .visibleCommands(commandAt(program, path))
        .map((item) => item.name())
        .filter((name) => name !== "help");
      expect(actual.sort(), path || "<root>").toEqual([...expected].sort());
    }
  });

  test("public options match the shared Python and TypeScript contract", () => {
    const program = createProgram();
    for (const [path, expected] of Object.entries(contract.options)) {
      const actual = commandAt(program, path)
        .options.filter((option) => !option.hidden)
        .map((option) => option.long)
        .filter((option): option is string => option !== undefined);
      expect(actual, path).toEqual(expect.arrayContaining(expected));
    }
  });

  test("msg send rejects missing or conflicting targets before runtime access", () => {
    const missing = runCli(["msg", "send", "--text", "hello"]);
    const conflicting = runCli([
      "msg",
      "send",
      "--to",
      "did:wba:example.test:user:a",
      "--group",
      "did:wba:example.test:group:a",
      "--text",
      "hello",
    ]);
    expect(missing.status).toBe(2);
    expect(conflicting.status).toBe(2);
    expect(missing.stderr).toContain("exactly one");
    expect(conflicting.stderr).toContain("exactly one");
  });

  test("numeric options reject invalid values before state or network access", () => {
    for (const args of [
      ["msg", "inbox", "--limit=-1"],
      ["msg", "history", "--with", "bob", "--limit=1.5"],
      ["group", "list", "--limit=NaN"],
      [
        "group",
        "messages",
        "--group",
        "did:wba:example.test:group:a",
        "--since-seq=-1",
      ],
    ]) {
      const result = runCli(args);
      expect(result.status, args.join(" ")).toBe(2);
      expect(result.stderr).toContain("Invalid input");
    }
  });
});
