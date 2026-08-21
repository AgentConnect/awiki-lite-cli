"""Runtime configuration loaded from explicit environment variables."""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from platformdirs import user_state_path

DEFAULT_SERVICE_URL = "https://awiki.ai"


@dataclass(frozen=True, slots=True)
class Settings:
    """Process-level endpoints and state location."""

    user_service_url: str
    message_service_url: str
    state_dir: Path
    ca_bundle: Path | None = None
    allow_private_network: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        """Load settings without reading an implicit repository-local dotenv file."""
        state_override = os.getenv("AWIKI_LITE_STATE_DIR")
        state_dir = (
            Path(state_override).expanduser()
            if state_override
            else user_state_path("awiki-lite-cli", "AgentConnect")
        )
        ca_value = os.getenv("AWIKI_LITE_CA_BUNDLE")
        return cls(
            user_service_url=os.getenv("AWIKI_USER_SERVICE_URL", DEFAULT_SERVICE_URL).rstrip("/"),
            message_service_url=os.getenv("AWIKI_MESSAGE_SERVICE_URL", DEFAULT_SERVICE_URL).rstrip(
                "/"
            ),
            state_dir=state_dir,
            ca_bundle=Path(ca_value).expanduser() if ca_value else None,
            allow_private_network=os.getenv("AWIKI_LITE_ALLOW_PRIVATE_NETWORK", "").lower()
            in {"1", "true", "yes"},
        )

    def tls_context(self) -> ssl.SSLContext | Literal[True]:
        """Return default verification or a context using the explicit private CA."""
        if self.ca_bundle is None:
            return True
        if not self.ca_bundle.is_file():
            raise ValueError("AWIKI_LITE_CA_BUNDLE must name a readable CA bundle file")
        try:
            return ssl.create_default_context(cafile=str(self.ca_bundle))
        except (OSError, ssl.SSLError) as exc:
            raise ValueError("AWIKI_LITE_CA_BUNDLE must name a readable CA bundle file") from exc
