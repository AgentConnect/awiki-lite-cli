"""Runtime configuration loaded from explicit environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_state_path

DEFAULT_SERVICE_URL = "https://awiki.ai"


@dataclass(frozen=True, slots=True)
class Settings:
    """Process-level endpoints and state location."""

    user_service_url: str
    message_service_url: str
    state_dir: Path

    @classmethod
    def from_env(cls) -> Settings:
        """Load settings without reading an implicit repository-local dotenv file."""
        state_override = os.getenv("AWIKI_LITE_STATE_DIR")
        state_dir = (
            Path(state_override).expanduser()
            if state_override
            else user_state_path("awiki-lite-cli", "AgentConnect")
        )
        return cls(
            user_service_url=os.getenv("AWIKI_USER_SERVICE_URL", DEFAULT_SERVICE_URL).rstrip("/"),
            message_service_url=os.getenv("AWIKI_MESSAGE_SERVICE_URL", DEFAULT_SERVICE_URL).rstrip(
                "/"
            ),
            state_dir=state_dir,
        )
