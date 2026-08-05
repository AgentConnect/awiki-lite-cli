import base64
import hashlib

import pytest

from awiki_lite_cli.domain.models import AttachmentRef
from awiki_lite_cli.infrastructure.attachment_manifest import build_manifest, parse_manifest


def attachment() -> AttachmentRef:
    digest = base64.urlsafe_b64encode(hashlib.sha256(b"payload").digest()).rstrip(b"=").decode()
    return AttachmentRef(
        "att-fixture",
        "https://objects.example.test/object-1",
        "report.pdf",
        "application/pdf",
        7,
        digest,
    )


def test_single_plain_manifest_round_trips_exact_wire_shape() -> None:
    value = build_manifest(attachment(), "report")
    assert value == {
        "attachments": [
            {
                "attachment_id": "att-fixture",
                "filename": "report.pdf",
                "mime_type": "application/pdf",
                "size": "7",
                "digest": {"alg": "sha-256", "value_b64u": attachment().sha256_b64u},
                "access_info": {"object_uri": "https://objects.example.test/object-1"},
                "encryption_info": {"mode": "none"},
            }
        ],
        "caption": "report",
        "primary_attachment_id": "att-fixture",
    }
    assert parse_manifest(value) == (attachment(), "report")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["attachments"].append(value["attachments"][0]),
        lambda value: value["attachments"][0].update(
            {"encryption_info": {"mode": "object-e2ee", "object_key_b64u": "secret"}}
        ),
        lambda value: value["attachments"][0].update({"filename": "../escape"}),
        lambda value: value["attachments"][0].update({"filename": "line\nbreak"}),
        lambda value: value["attachments"][0].update({"size": 7}),
        lambda value: value.update({"primary_attachment_id": "different"}),
        lambda value: value.update({"unknown": True}),
    ],
)
def test_manifest_parser_rejects_multifile_e2ee_and_noncanonical_shapes(mutation) -> None:  # type: ignore[no-untyped-def]
    value = build_manifest(attachment(), None)
    mutation(value)
    with pytest.raises(RuntimeError):
        parse_manifest(value)
