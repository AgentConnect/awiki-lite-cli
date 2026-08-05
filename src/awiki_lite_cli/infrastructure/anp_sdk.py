"""Single import boundary for the sibling ANP Python SDK."""

from dataclasses import dataclass
from importlib.metadata import version

from anp.authentication import (  # type: ignore[import-untyped]
    PROFILE_CORE_BINDING_V1,
    PROFILE_DIRECT_BASE_V1,
    PROFILE_GROUP_BASE_V1,
    PROFILE_IDENTITY_DISCOVERY_V1,
)


@dataclass(frozen=True, slots=True)
class AnpSdkInfo:
    version: str
    allowed_profiles: tuple[str, ...]


def sdk_info() -> AnpSdkInfo:
    """Expose only the non-E2EE profiles allowed by this client."""
    return AnpSdkInfo(
        version=version("anp"),
        allowed_profiles=(
            PROFILE_CORE_BINDING_V1,
            PROFILE_IDENTITY_DISCOVERY_V1,
            PROFILE_DIRECT_BASE_V1,
            PROFILE_GROUP_BASE_V1,
        ),
    )
