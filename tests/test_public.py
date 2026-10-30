import unicodedata

import pytest

from bayyina_guard.passwords import hash_password, verify_password
from bayyina_guard.policy import Document, User, authorize
from bayyina_guard.validation import ValidationError, validate_upload

PDF = "application/pdf"


def meta(**kw):
    base = dict(filename="عقد.pdf", content_type=PDF, size_bytes=10,
                matter_id="MAT-2026-00042", first_bytes=b"%PDF-1.7")
    base.update(kw)
    return base


def test_arabic_filename_accepted_and_renamed():
    c = validate_upload(meta())
    assert c.display_name == "عقد.pdf"
    assert c.stored_name != "عقد.pdf" and c.stored_name.endswith(".pdf")


def test_all_errors_reported_together():
    with pytest.raises(ValidationError) as e:
        validate_upload(meta(filename="../x.pdf", size_bytes=0, matter_id="bad", first_bytes="no"))
    assert {"filename", "size_bytes", "matter_id", "first_bytes"} <= set(e.value.errors)


def test_client_denied_other_clients_contract():
    u = User("u1", "client", client_id="CL-A")
    d = Document("d1", "CL-B", "MAT-2026-00001")
    assert authorize(u, "read", d) == authorize(u, "read", d)
    assert authorize(u, "read", d).reason == "tenant_mismatch"


def test_associate_on_matter_can_comment():
    u = User("u2", "associate", matters=frozenset({"MAT-2026-00001"}))
    assert authorize(u, "comment", Document("d1", "CL-A", "MAT-2026-00001")).allowed


def test_password_round_trip():
    h = hash_password("correct horse")
    assert verify_password("correct horse", h) and not verify_password("wrong horse!", h)
