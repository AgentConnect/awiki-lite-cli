from __future__ import annotations

import plistlib
import subprocess
from pathlib import Path

from awiki_lite_cli.infrastructure.listener_service import (
    SERVICE_NAME,
    CommandRunner,
    LaunchAgentManager,
    ServiceContext,
    SystemdUserManager,
    WindowsTaskManager,
    service_manager,
)


class FakeRunner(CommandRunner):
    def __init__(self, outputs: list[tuple[int, str]] | None = None) -> None:
        self.outputs = list(outputs or [])
        self.commands: list[list[str]] = []

    def run(
        self, command: list[str] | tuple[str, ...], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(command))
        returncode, stdout = self.outputs.pop(0) if self.outputs else (0, "")
        return subprocess.CompletedProcess(command, returncode, stdout, "")


def context(tmp_path: Path) -> ServiceContext:
    return ServiceContext(
        Path("/opt/awiki venv/bin/python"),
        tmp_path / "state directory",
        "https://messages.example",
        tmp_path / "home",
        501,
    )


def test_systemd_unit_is_user_scoped_and_contains_no_credentials(tmp_path: Path) -> None:
    manager = SystemdUserManager(context(tmp_path), FakeRunner())
    unit = manager.unit_content()
    assert "WantedBy=default.target" in unit
    assert "runtime listener run --service-mode" in unit
    assert "AWIKI_LITE_STATE_DIR" in unit
    assert "AWIKI_MESSAGE_SERVICE_URL" in unit
    assert "Bearer" not in unit
    assert "token" not in unit.lower()


def test_systemd_install_writes_unit_and_runs_user_manager_commands(tmp_path: Path) -> None:
    runner = FakeRunner([(0, "not-found\ninactive\n"), (0, ""), (0, "")])
    manager = SystemdUserManager(context(tmp_path), runner)
    manager.install()
    assert manager.unit_path.is_file()
    assert runner.commands[:2] == [
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", manager.unit_name],
    ]


def test_launchagent_plist_uses_argument_array_and_nonsecret_environment(tmp_path: Path) -> None:
    manager = LaunchAgentManager(context(tmp_path), FakeRunner())
    value = plistlib.loads(manager.plist_content())
    assert value["Label"] == SERVICE_NAME
    assert value["ProgramArguments"][-4:] == ["runtime", "listener", "run", "--service-mode"]
    assert value["KeepAlive"] == {"SuccessfulExit": False}
    assert value["EnvironmentVariables"] == {
        "AWIKI_LITE_STATE_DIR": str(context(tmp_path).state_dir),
        "AWIKI_MESSAGE_SERVICE_URL": "https://messages.example",
        "PYTHONUNBUFFERED": "1",
    }


def test_launchagent_status_parses_running_pid(tmp_path: Path) -> None:
    manager = LaunchAgentManager(
        context(tmp_path), FakeRunner([(0, "state = running\npid = 123\n")])
    )
    manager.plist_path.parent.mkdir(parents=True)
    manager.plist_path.write_bytes(manager.plist_content())
    status = manager.status()
    assert status.installed
    assert status.running
    assert status.state == "running"


def test_launchagent_stop_is_idempotent_when_not_installed(tmp_path: Path) -> None:
    runner = FakeRunner()
    status = LaunchAgentManager(context(tmp_path), runner).stop()
    assert not status.installed
    assert runner.commands == []


def test_windows_service_command_binds_explicit_interpreter_and_state(tmp_path: Path) -> None:
    manager = WindowsTaskManager(context(tmp_path), FakeRunner([(1, "")]))
    command = manager._service_command()
    assert "awiki_lite_cli" in command
    assert "runtime listener run --service-mode" in command
    assert str(context(tmp_path).state_dir) in command
    assert "https://messages.example" in command
    assert "Bearer" not in command


def test_windows_install_uses_limited_interactive_user_task(tmp_path: Path) -> None:
    runner = FakeRunner([(1, ""), (0, ""), (0, "task"), (0, "Ready")])
    status = WindowsTaskManager(context(tmp_path), runner).install()
    create = runner.commands[1]
    assert create[:2] == ["schtasks.exe", "/Create"]
    assert create[create.index("/RL") : create.index("/RL") + 2] == ["/RL", "LIMITED"]
    assert "/IT" in create
    assert status.installed and not status.running


def test_service_manager_selects_all_supported_platforms(tmp_path: Path) -> None:
    selected_context = context(tmp_path)
    assert isinstance(
        service_manager(
            Path("state"), "https://example", platform="linux", context=selected_context
        ),
        SystemdUserManager,
    )
    assert isinstance(
        service_manager(
            Path("state"), "https://example", platform="darwin", context=selected_context
        ),
        LaunchAgentManager,
    )
    assert isinstance(
        service_manager(
            Path("state"), "https://example", platform="win32", context=selected_context
        ),
        WindowsTaskManager,
    )
