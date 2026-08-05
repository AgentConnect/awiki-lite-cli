#!/usr/bin/env python3
"""Destructive opt-in remote E2E for ordinary groups and plain P7 attachments."""

from __future__ import annotations

import argparse
import asyncio
import secrets
import tempfile
from pathlib import Path

import httpx
from remote_e2e import (
    SERVICE_URL,
    TARGET,
    _cleanup,
    _env_values,
    _operator_command,
    _register,
    _resolve_peer_otp,
)

from awiki_lite_cli.application.attachments import AttachmentWorkflow
from awiki_lite_cli.application.groups import GroupWorkflow
from awiki_lite_cli.application.registration import RegistrationWorkflow
from awiki_lite_cli.domain.models import AttachmentContext, AuthenticatedIdentity
from awiki_lite_cli.infrastructure.attachment_service import AttachmentService
from awiki_lite_cli.infrastructure.group_service import GroupService
from awiki_lite_cli.infrastructure.message_service import MessageService
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore
from awiki_lite_cli.infrastructure.user_service import UserService


def _attachments(client: httpx.AsyncClient, store: SecureStateStore) -> AttachmentWorkflow:
    return AttachmentWorkflow(
        AttachmentService(client, SERVICE_URL),
        MessageService(client, SERVICE_URL),
        GroupService(client, SERVICE_URL),
        store,
    )


async def _run(repo_root: Path, values: dict[str, str]) -> None:
    phone_a = values.get("DEV_OTP_PHONE", "").strip()
    otp_a = values.get("DEV_OTP_CODE", "").strip()
    phone_b = values.get("AWIKI_MULTI_DEVICE_E2E_PEER_PHONE", "").strip()
    if not phone_a or not otp_a or not phone_b:
        raise RuntimeError("dedicated E2E registration configuration is incomplete")

    suffix = secrets.token_hex(4)
    handle_a = f"litega{suffix}"
    handle_b = f"litegb{suffix}"
    passphrase_a = secrets.token_urlsafe(32)
    passphrase_b = secrets.token_urlsafe(32)
    operator = _operator_command(repo_root)
    direct_bytes = b"awiki-lite direct attachment e2e\x00"
    group_bytes = b"awiki-lite group attachment e2e\x00"

    with tempfile.TemporaryDirectory(prefix="awiki-lite-v02-e2e-") as temporary:
        root = Path(temporary)
        store_a = SecureStateStore(root / "a")
        store_b = SecureStateStore(root / "b")
        direct_file = root / "direct.bin"
        group_file = root / "group.bin"
        direct_file.write_bytes(direct_bytes)
        group_file.write_bytes(group_bytes)
        download_dir = root / "downloads"
        download_dir.mkdir(mode=0o700)

        async with httpx.AsyncClient(
            timeout=30.0, trust_env=False, follow_redirects=False
        ) as client:
            await _register(
                client,
                store_a,
                handle_a,
                phone_a,
                otp_a,
                passphrase_a,
                tolerate_sms_failure=True,
            )
            flow_b = RegistrationWorkflow(UserService(client, SERVICE_URL), store_b, SERVICE_URL)
            try:
                canonical_b, canonical_phone_b, domain_b = await flow_b.begin(handle_b, phone_b)
            except JsonRpcFailure:
                canonical_b, canonical_phone_b, domain_b = handle_b, phone_b, "awiki.info"
            otp_b = _resolve_peer_otp(operator, phone_b, handle_b)
            await flow_b.finish(canonical_b, canonical_phone_b, domain_b, otp_b, passphrase_b)

            unlocked_a = store_a.unlock(passphrase_a)
            unlocked_b = store_b.unlock(passphrase_b)
            auth_b = AuthenticatedIdentity(unlocked_b.identity, unlocked_b.session)
            group_a = GroupWorkflow(GroupService(client, SERVICE_URL), store_a)
            group_b = GroupWorkflow(GroupService(client, SERVICE_URL), store_b)

            group = await group_a.create(unlocked_a, "AWiki Lite v0.2 E2E")
            await group_a.add(unlocked_a, group.group_did, unlocked_b.identity.did)
            sent_a = await group_a.send(unlocked_a, group.group_did, "A to group")
            sent_b = await group_b.send(unlocked_b, group.group_did, "B to group")
            rows_a, _ = await group_a.messages(group.group_did, 100, 0)
            rows_b, _ = await group_b.messages(group.group_did, 100, 0)
            expected_text = {sent_a.message_id, sent_b.message_id}
            assert expected_text.issubset({row.message_id for row in rows_a})
            assert expected_text.issubset({row.message_id for row in rows_b})

            direct_message_id, direct_attachment_id = await _attachments(client, store_a).send(
                unlocked_a,
                direct_file,
                recipient_did=unlocked_b.identity.did,
                group_did=None,
                caption="direct e2e",
            )
            inbox_b, _ = await MessageService(client, SERVICE_URL).inbox(auth_b, 100)
            direct_message = next(
                message for message in inbox_b if message.message_id == direct_message_id
            )
            store_b.save_attachment_contexts(
                [
                    AttachmentContext(
                        direct_message.message_id,
                        direct_message.sender_did,
                        direct_message.target_did,
                        None,
                        direct_message.attachments[0],
                    )
                ]
            )
            direct_download = await _attachments(client, store_b).download(
                auth_b,
                direct_message_id,
                direct_attachment_id,
                download_dir,
            )
            assert direct_download.read_bytes() == direct_bytes

            group_message_id, group_attachment_id = await _attachments(client, store_a).send(
                unlocked_a,
                group_file,
                recipient_did=None,
                group_did=group.group_did,
                caption="group e2e",
            )
            projected, _ = await group_b.messages(group.group_did, 100, 0)
            assert group_message_id in {row.message_id for row in projected}
            group_download = await _attachments(client, store_b).download(
                auth_b,
                group_message_id,
                group_attachment_id,
                download_dir,
            )
            assert group_download.read_bytes() == group_bytes

            # Exercise read authentication for both identities after all mutations.
            assert (await group_a.info(group.group_did)).group_did == group.group_did
            assert (await group_b.info(group.group_did)).group_did == group.group_did


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, choices=[TARGET])
    args = parser.parse_args()
    if args.target != TARGET:
        raise SystemExit("unsupported remote E2E target")
    repo_root = Path(__file__).resolve().parents[2]
    values = _env_values(repo_root / "user-service" / ".env")
    removed_before = _cleanup(repo_root)
    try:
        asyncio.run(_run(repo_root, values))
    finally:
        removed_after = _cleanup(repo_root)
    print(
        "remote v0.2 E2E passed: group A/B text, direct attachment and group attachment "
        f"verified; scoped cleanup removed {removed_before + removed_after} rows"
    )


if __name__ == "__main__":
    main()
