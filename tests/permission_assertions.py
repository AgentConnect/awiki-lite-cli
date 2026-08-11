import os
import stat
from pathlib import Path


def assert_private_path(path: Path, *, directory: bool) -> None:
    """Verify the platform-native private permissions used by the state store."""
    if os.name != "nt":
        expected = 0o700 if directory else 0o600
        assert stat.S_IMODE(path.stat().st_mode) == expected
        return

    import ntsecuritycon  # type: ignore[import-untyped]
    import win32api  # type: ignore[import-untyped]
    import win32con  # type: ignore[import-untyped]
    import win32security  # type: ignore[import-untyped]

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
    descriptor = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
    )

    assert descriptor.GetSecurityDescriptorOwner() == user_sid
    control, _revision = descriptor.GetSecurityDescriptorControl()
    assert control & win32security.SE_DACL_PROTECTED

    dacl = descriptor.GetSecurityDescriptorDacl()
    assert dacl is not None
    assert dacl.GetAceCount() == 2

    expected_flags = (
        win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE if directory else 0
    )
    found_sids = []
    for index in range(dacl.GetAceCount()):
        (ace_type, ace_flags), access_mask, sid = dacl.GetAce(index)
        assert ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE
        assert ace_flags == expected_flags
        assert access_mask == ntsecuritycon.FILE_ALL_ACCESS
        assert sid in (user_sid, system_sid)
        found_sids.append(sid)

    assert any(sid == user_sid for sid in found_sids)
    assert any(sid == system_sid for sid in found_sids)
