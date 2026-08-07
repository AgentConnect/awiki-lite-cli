"""Cross-platform service-manager adapters for the WebSocket listener."""

from __future__ import annotations

import os
import plistlib
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

SERVICE_NAME = "com.agentconnect.awiki-lite-listener"
SERVICE_DISPLAY_NAME = "AWiki Lite WebSocket Listener"
SERVICE_DESCRIPTION = "Receives authenticated AWiki synchronization notifications."


class ListenerServiceError(RuntimeError):
    """Safe service-manager error that excludes command output and credentials."""


@dataclass(frozen=True, slots=True)
class ListenerServiceStatus:
    platform: str
    installed: bool
    running: bool
    state: str


@dataclass(frozen=True, slots=True)
class ServiceContext:
    executable: Path
    state_dir: Path
    message_service_url: str
    home: Path
    uid: int | None = None

    @classmethod
    def current(cls, state_dir: Path, message_service_url: str) -> ServiceContext:
        try:
            home = Path.home()
        except RuntimeError as exc:
            raise ListenerServiceError("the current user home directory is unavailable") from exc
        uid = os.getuid() if hasattr(os, "getuid") else None
        return cls(Path(sys.executable), state_dir, message_service_url, home, uid)


class CommandRunner:
    """Execute fixed service-manager commands without exposing their output in errors."""

    def run(
        self, command: Sequence[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                list(command),
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ListenerServiceError("the platform service manager is unavailable") from exc
        if check and result.returncode != 0:
            raise ListenerServiceError("the platform service manager rejected the operation")
        return result


class ListenerServiceManager:
    platform = "unsupported"

    def __init__(self, context: ServiceContext, runner: CommandRunner | None = None) -> None:
        self.context = context
        self.runner = runner or CommandRunner()

    def status(self) -> ListenerServiceStatus:
        raise ListenerServiceError("listener services are unsupported on this operating system")

    def install(self) -> ListenerServiceStatus:
        raise ListenerServiceError("listener services are unsupported on this operating system")

    def start(self) -> ListenerServiceStatus:
        raise ListenerServiceError("listener services are unsupported on this operating system")

    def stop(self) -> ListenerServiceStatus:
        raise ListenerServiceError("listener services are unsupported on this operating system")

    def restart(self) -> ListenerServiceStatus:
        self.stop()
        return self.start()

    def uninstall(self) -> ListenerServiceStatus:
        raise ListenerServiceError("listener services are unsupported on this operating system")


class SystemdUserManager(ListenerServiceManager):
    platform = "linux-systemd-user"

    @property
    def unit_name(self) -> str:
        return f"{SERVICE_NAME}.service"

    @property
    def unit_path(self) -> Path:
        return self.context.home / ".config" / "systemd" / "user" / self.unit_name

    def unit_content(self) -> str:
        command = " ".join(
            _systemd_quote(item)
            for item in (
                str(self.context.executable),
                "-m",
                "awiki_lite_cli",
                "listener",
                "run",
                "--service-mode",
                "--state-dir",
                str(self.context.state_dir),
                "--message-service-url",
                self.context.message_service_url,
            )
        )
        return (
            "[Unit]\n"
            f"Description={SERVICE_DESCRIPTION}\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"ExecStart={command}\n"
            f"Environment=AWIKI_LITE_STATE_DIR={_systemd_quote(str(self.context.state_dir))}\n"
            "Environment=AWIKI_MESSAGE_SERVICE_URL="
            f"{_systemd_quote(self.context.message_service_url)}\n"
            "Environment=PYTHONUNBUFFERED=1\n"
            "Restart=on-failure\n"
            "RestartSec=1s\n\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        )

    def status(self) -> ListenerServiceStatus:
        result = self.runner.run(
            [
                "systemctl",
                "--user",
                "show",
                self.unit_name,
                "--property=LoadState",
                "--property=ActiveState",
                "--value",
            ],
            check=False,
        )
        lines = result.stdout.splitlines()
        load_state = lines[0].strip() if lines else "not-found"
        active_state = lines[1].strip() if len(lines) > 1 else "inactive"
        installed = self.unit_path.is_file() and load_state != "not-found"
        running = installed and active_state in {"active", "activating"}
        return ListenerServiceStatus(self.platform, installed, running, active_state)

    def install(self) -> ListenerServiceStatus:
        _atomic_text(self.unit_path, self.unit_content())
        self.runner.run(["systemctl", "--user", "daemon-reload"])
        self.runner.run(["systemctl", "--user", "enable", self.unit_name])
        return self.status()

    def start(self) -> ListenerServiceStatus:
        if not self.status().installed:
            self.install()
        self.runner.run(["systemctl", "--user", "start", self.unit_name])
        return self.status()

    def stop(self) -> ListenerServiceStatus:
        if self.status().installed:
            self.runner.run(["systemctl", "--user", "stop", self.unit_name])
        return self.status()

    def restart(self) -> ListenerServiceStatus:
        if not self.status().installed:
            raise ListenerServiceError("listener service is not installed")
        self.runner.run(["systemctl", "--user", "restart", self.unit_name])
        return self.status()

    def uninstall(self) -> ListenerServiceStatus:
        current = self.status()
        if current.installed:
            if current.running:
                self.runner.run(["systemctl", "--user", "stop", self.unit_name])
            self.runner.run(["systemctl", "--user", "disable", self.unit_name])
        if self.unit_path.exists():
            self.unit_path.unlink()
        self.runner.run(["systemctl", "--user", "daemon-reload"])
        return ListenerServiceStatus(self.platform, False, False, "not-installed")


class LaunchAgentManager(ListenerServiceManager):
    platform = "macos-launchagent"

    @property
    def plist_path(self) -> Path:
        return self.context.home / "Library" / "LaunchAgents" / f"{SERVICE_NAME}.plist"

    @property
    def target(self) -> str:
        if self.context.uid is None:
            raise ListenerServiceError("the current user identifier is unavailable")
        return f"gui/{self.context.uid}/{SERVICE_NAME}"

    @property
    def domain(self) -> str:
        if self.context.uid is None:
            raise ListenerServiceError("the current user identifier is unavailable")
        return f"gui/{self.context.uid}"

    def plist_content(self) -> bytes:
        logs = self.context.state_dir / "logs"
        value = {
            "Label": SERVICE_NAME,
            "ProgramArguments": [
                str(self.context.executable),
                "-m",
                "awiki_lite_cli",
                "listener",
                "run",
                "--service-mode",
            ],
            "EnvironmentVariables": {
                "AWIKI_LITE_STATE_DIR": str(self.context.state_dir),
                "AWIKI_MESSAGE_SERVICE_URL": self.context.message_service_url,
                "PYTHONUNBUFFERED": "1",
            },
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ProcessType": "Background",
            "StandardOutPath": str(logs / "listener.out.log"),
            "StandardErrorPath": str(logs / "listener.err.log"),
        }
        return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)

    def status(self) -> ListenerServiceStatus:
        installed = self.plist_path.is_file()
        if not installed:
            return ListenerServiceStatus(self.platform, False, False, "not-installed")
        result = self.runner.run(["launchctl", "print", self.target], check=False)
        output = result.stdout
        running = result.returncode == 0 and bool(
            re.search(r"(?:^|\n)\s*state\s*=\s*running\s*(?:\n|$)", output)
            or re.search(r"(?:^|\n)\s*pid\s*=\s*[1-9][0-9]*\s*(?:\n|$)", output)
        )
        state = "running" if running else ("loaded" if result.returncode == 0 else "unloaded")
        return ListenerServiceStatus(self.platform, True, running, state)

    def install(self) -> ListenerServiceStatus:
        (self.context.state_dir / "logs").mkdir(mode=0o700, parents=True, exist_ok=True)
        _atomic_bytes(self.plist_path, self.plist_content())
        return self.status()

    def start(self) -> ListenerServiceStatus:
        self.install()
        current = self.status()
        if current.state == "unloaded":
            self.runner.run(["launchctl", "bootstrap", self.domain, str(self.plist_path)])
        else:
            self.runner.run(["launchctl", "kickstart", "-k", self.target])
        return self.status()

    def stop(self) -> ListenerServiceStatus:
        current = self.status()
        if current.installed and current.state != "unloaded":
            self.runner.run(["launchctl", "bootout", self.domain, str(self.plist_path)])
        return self.status()

    def restart(self) -> ListenerServiceStatus:
        if not self.status().installed:
            raise ListenerServiceError("listener service is not installed")
        self.stop()
        return self.start()

    def uninstall(self) -> ListenerServiceStatus:
        if self.status().installed:
            self.stop()
            self.plist_path.unlink(missing_ok=True)
        return ListenerServiceStatus(self.platform, False, False, "not-installed")


class WindowsTaskManager(ListenerServiceManager):
    """Per-user listener hosted by Task Scheduler in the interactive account."""

    platform = "windows-scheduled-task"
    task_name = r"\AgentConnect\AWikiLiteListener"

    def _service_command(self) -> str:
        return subprocess.list2cmdline(
            [
                str(self.context.executable),
                "-m",
                "awiki_lite_cli",
                "listener",
                "run",
                "--service-mode",
                "--state-dir",
                str(self.context.state_dir),
                "--message-service-url",
                self.context.message_service_url,
            ]
        )

    def status(self) -> ListenerServiceStatus:
        result = self.runner.run(
            ["schtasks.exe", "/Query", "/TN", self.task_name, "/FO", "LIST"], check=False
        )
        if result.returncode != 0:
            return ListenerServiceStatus(self.platform, False, False, "not-installed")
        state_result = self.runner.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-ScheduledTask -TaskName 'AWikiLiteListener' "
                "-TaskPath '\\AgentConnect\\').State.ToString()",
            ],
            check=False,
        )
        state = state_result.stdout.strip().lower() or "unknown"
        return ListenerServiceStatus(self.platform, True, state == "running", state)

    def install(self) -> ListenerServiceStatus:
        if self.status().installed:
            raise ListenerServiceError("listener service is already installed; uninstall it first")
        self.runner.run(
            [
                "schtasks.exe",
                "/Create",
                "/TN",
                self.task_name,
                "/TR",
                self._service_command(),
                "/SC",
                "ONLOGON",
                "/RL",
                "LIMITED",
                "/IT",
                "/F",
            ]
        )
        return self.status()

    def start(self) -> ListenerServiceStatus:
        if not self.status().installed:
            self.install()
        self.runner.run(["schtasks.exe", "/Run", "/TN", self.task_name])
        return self.status()

    def stop(self) -> ListenerServiceStatus:
        current = self.status()
        if current.installed and current.running:
            self.runner.run(["schtasks.exe", "/End", "/TN", self.task_name])
        return self.status()

    def restart(self) -> ListenerServiceStatus:
        if not self.status().installed:
            raise ListenerServiceError("listener service is not installed")
        self.stop()
        return self.start()

    def uninstall(self) -> ListenerServiceStatus:
        if self.status().installed:
            self.stop()
            self.runner.run(["schtasks.exe", "/Delete", "/TN", self.task_name, "/F"])
        return ListenerServiceStatus(self.platform, False, False, "not-installed")


def service_manager(
    state_dir: Path,
    message_service_url: str,
    *,
    platform: str | None = None,
    runner: CommandRunner | None = None,
    context: ServiceContext | None = None,
) -> ListenerServiceManager:
    selected = platform or sys.platform
    resolved = context or ServiceContext.current(state_dir, message_service_url)
    if selected.startswith("linux"):
        return SystemdUserManager(resolved, runner)
    if selected == "darwin":
        return LaunchAgentManager(resolved, runner)
    if selected in {"win32", "cygwin"}:
        return WindowsTaskManager(resolved, runner)
    return ListenerServiceManager(resolved, runner)


def _systemd_quote(value: str) -> str:
    return shlex.quote(value).replace("%", "%%")


def _atomic_text(path: Path, content: str) -> None:
    _atomic_bytes(path, content.encode())


def _atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if os.name != "nt":
            cast(Any, os).fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise
