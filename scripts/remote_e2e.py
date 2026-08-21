#!/usr/bin/env python3
"""Opt-in AWiki testing E2E for v0.1 registration and plain Direct messaging."""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx

from awiki_lite_cli.application.registration import RegistrationWorkflow
from awiki_lite_cli.domain.models import AuthenticatedIdentity
from awiki_lite_cli.infrastructure.anp_sdk import generate_identity
from awiki_lite_cli.infrastructure.message_service import MessageService
from awiki_lite_cli.infrastructure.rpc import JsonRpcFailure
from awiki_lite_cli.infrastructure.state import SecureStateStore
from awiki_lite_cli.infrastructure.user_service import UserService

TARGET = "awiki-info-testing"
SERVICE_URL = "https://awiki.info"
OPERATOR_PROFILE = "awiki-info-managed-local-v1"


def _env_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _operator_command(repo_root: Path) -> tuple[str, ...]:
    system_test_src = repo_root / "awiki-system-test" / "src"
    sys.path.insert(0, str(system_test_src))
    from helpers.operator_profiles import reviewed_operator_profile

    profile = reviewed_operator_profile(OPERATOR_PROFILE)
    if profile.target_name != TARGET or profile.service_url != SERVICE_URL:
        raise RuntimeError("reviewed operator profile does not match the selected target")
    return profile.command("otp")


def _resolve_peer_otp(command: tuple[str, ...], phone: str, handle: str) -> str:
    scope = json.dumps(
        {
            "phone": phone,
            "purpose": "awiki.identity.register.v1",
            "target_handle": handle,
            "target_handle_domain": "awiki.info",
            "operation_id": None,
            "recovery_session_id": None,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    completed = subprocess.run(
        command,
        input=scope,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0 or len(completed.stdout.encode()) > 1024:
        raise RuntimeError("reviewed OTP operator failed")
    try:
        payload: Any = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeError):
        raise RuntimeError("reviewed OTP operator returned invalid data") from None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"otp"}
        or not isinstance(payload["otp"], str)
        or len(payload["otp"]) != 6
        or not payload["otp"].isascii()
        or not payload["otp"].isdigit()
    ):
        raise RuntimeError("reviewed OTP operator returned invalid data")
    return payload["otp"]


def _cleanup(repo_root: Path) -> int:
    system_test = repo_root / "awiki-system-test"
    program = """
from pathlib import Path
from dotenv import dotenv_values
from helpers.db_cleanup import cleanup_test_data
values = dotenv_values(Path('../user-service/.env'))
phones = [str(values.get(key) or '').strip() for key in (
    'DEV_OTP_PHONE', 'AWIKI_MULTI_DEVICE_E2E_PEER_PHONE')]
if not all(phones):
    raise SystemExit(2)
report = cleanup_test_data(phones=phones, include_message_service=True)
print(report.total_deleted_rows)
"""
    completed = subprocess.run(
        [str(system_test / ".venv/bin/python"), "-c", program],
        cwd=system_test,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError("scoped E2E cleanup failed")
    try:
        return int(completed.stdout.strip())
    except ValueError:
        raise RuntimeError("scoped E2E cleanup returned invalid data") from None


async def _register(
    client: httpx.AsyncClient,
    store: SecureStateStore,
    handle: str,
    phone: str,
    otp: str,
    passphrase: str,
    *,
    tolerate_sms_failure: bool,
) -> None:
    workflow = RegistrationWorkflow(
        UserService(client, SERVICE_URL),
        MessageService(client, SERVICE_URL),
        store,
        SERVICE_URL,
        generate_identity,
    )
    try:
        canonical_handle, canonical_phone, domain, _ = await workflow.begin(handle, phone)
    except JsonRpcFailure:
        if not tolerate_sms_failure:
            raise
        canonical_handle, canonical_phone, domain = handle, phone, "awiki.info"
    await workflow.finish(canonical_handle, canonical_phone, domain, otp, passphrase)


async def _run(repo_root: Path, values: dict[str, str]) -> None:
    phone_a = values.get("DEV_OTP_PHONE", "").strip()
    otp_a = values.get("DEV_OTP_CODE", "").strip()
    phone_b = values.get("AWIKI_MULTI_DEVICE_E2E_PEER_PHONE", "").strip()
    if not phone_a or not otp_a or not phone_b:
        raise RuntimeError("dedicated E2E registration configuration is incomplete")

    suffix = secrets.token_hex(4)
    handle_a = f"litea{suffix}"
    handle_b = f"liteb{suffix}"
    passphrase_a = secrets.token_urlsafe(32)
    passphrase_b = secrets.token_urlsafe(32)
    operator = _operator_command(repo_root)

    with tempfile.TemporaryDirectory(prefix="awiki-lite-e2e-") as temporary:
        store_a = SecureStateStore(Path(temporary) / "a")
        store_b = SecureStateStore(Path(temporary) / "b")
        async with httpx.AsyncClient(timeout=20.0, trust_env=False) as client:
            await _register(
                client,
                store_a,
                handle_a,
                phone_a,
                otp_a,
                passphrase_a,
                tolerate_sms_failure=True,
            )
            service_b = UserService(client, SERVICE_URL)
            flow_b = RegistrationWorkflow(
                service_b,
                MessageService(client, SERVICE_URL),
                store_b,
                SERVICE_URL,
                generate_identity,
            )
            try:
                canonical_b, canonical_phone_b, domain_b, _ = await flow_b.begin(handle_b, phone_b)
            except JsonRpcFailure:
                canonical_b, canonical_phone_b, domain_b = handle_b, phone_b, "awiki.info"
            otp_b = _resolve_peer_otp(operator, phone_b, handle_b)
            await flow_b.finish(canonical_b, canonical_phone_b, domain_b, otp_b, passphrase_b)

            unlocked_a = store_a.unlock(passphrase_a)
            unlocked_b = store_b.unlock(passphrase_b)
            auth_a = AuthenticatedIdentity(unlocked_a.identity, unlocked_a.session)
            auth_b = AuthenticatedIdentity(unlocked_b.identity, unlocked_b.session)
            messages = MessageService(client, SERVICE_URL)

            pending = store_a.prepare_send(unlocked_b.identity.did, "A to B")
            sent = await messages.send(
                unlocked_a,
                unlocked_b.identity.did,
                "A to B",
                operation_id=pending.operation_id,
                message_id=pending.message_id,
                created_at=pending.created_at,
                proof_created=pending.proof_created,
                proof_nonce=pending.proof_nonce,
            )
            duplicate = await messages.send(
                unlocked_a,
                unlocked_b.identity.did,
                "A to B",
                operation_id=pending.operation_id,
                message_id=pending.message_id,
                created_at=pending.created_at,
                proof_created=pending.proof_created,
                proof_nonce=pending.proof_nonce,
            )
            assert duplicate.message_id == sent.message_id
            store_a.complete_send(pending)

            inbox_b, _ = await messages.inbox(auth_b, 20)
            assert [item.message_id for item in inbox_b].count(sent.message_id) == 1
            assert await messages.mark_read(auth_b, [sent.message_id]) == 1
            inbox_after_read, _ = await messages.inbox(auth_b, 20)
            assert sent.message_id not in {item.message_id for item in inbox_after_read}

            reply = await messages.send(unlocked_b, unlocked_a.identity.did, "B to A")
            inbox_a, _ = await messages.inbox(auth_a, 20)
            assert reply.message_id in {item.message_id for item in inbox_a}
            history_a, _ = await messages.history(auth_a, unlocked_b.identity.did, 20)
            history_b, _ = await messages.history(auth_b, unlocked_a.identity.did, 20)
            expected = {sent.message_id, reply.message_id}
            assert expected.issubset({item.message_id for item in history_a})
            assert expected.issubset({item.message_id for item in history_b})


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
        "remote E2E passed: registration A/B, idempotent A->B, mark-read, "
        f"B->A, both histories; scoped cleanup removed {removed_before + removed_after} rows"
    )


if __name__ == "__main__":
    main()
