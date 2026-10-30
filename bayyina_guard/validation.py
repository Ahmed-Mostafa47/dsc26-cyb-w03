"""Part 1: upload validation. An allow-list: anything not explicitly fine is refused."""
from __future__ import annotations

import re
import secrets
import unicodedata
from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024

# Invisible direction controls that can make "invoice<RLO>fdp.exe" display as "...exe.pdf".
_BIDI = frozenset(
    "\u061c\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2066\u2067\u2068\u2069"
)
_CONTENT_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
_MAGIC = {"pdf": b"%PDF-", "docx": b"PK\x03\x04"}
# fullmatch + ASCII: no trailing-newline trick, no Arabic-Indic digits.
_MATTER_RE = re.compile(r"MAT-[0-9]{4}-[0-9]{5}", re.ASCII)


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(errors)
        self.errors = errors


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str
    display_name: str
    extension: str
    content_type: str
    size_bytes: int
    matter_id: str


def _check_filename(value) -> tuple[str | None, str | None, str | None]:
    """Return (display_name, extension, error). On error the first two are None."""
    if not isinstance(value, str):
        return None, None, "filename must be a string"
    name = unicodedata.normalize("NFC", value)  # normalise BEFORE checking
    if not 1 <= len(name) <= 120:
        return None, None, "filename must be 1 to 120 characters"
    for ch in name:
        if unicodedata.category(ch) == "Cc":
            return None, None, "filename contains a control character"
        if ch in _BIDI:
            return None, None, "filename contains a bidirectional control character"
    if "/" in name or "\\" in name:
        return None, None, "filename must not contain a path separator"
    if ".." in name:
        return None, None, "filename must not contain '..'"
    if name.startswith("."):
        return None, None, "filename must not start with '.'"
    base, dot, ext = name.rpartition(".")
    if not dot:
        return None, None, "filename needs an extension"
    ext = ext.lower()
    if ext not in _CONTENT_TYPES:
        return None, None, "extension must be pdf or docx"
    if not base.strip():
        return None, None, "filename needs a name before the extension"
    return name, ext, None


def validate_upload(meta: dict) -> CleanUpload:
    if not isinstance(meta, dict):
        raise ValidationError({k: "missing" for k in
                               ("filename", "content_type", "size_bytes", "matter_id", "first_bytes")})
    errors: dict[str, str] = {}

    display, ext, err = _check_filename(meta.get("filename"))
    if err:
        errors["filename"] = err

    # content_type
    ctype = meta.get("content_type")
    if not isinstance(ctype, str):
        errors["content_type"] = "content_type must be a string"
    elif ext is not None and ctype != _CONTENT_TYPES[ext]:
        errors["content_type"] = "content_type does not match the file extension"

    # first_bytes (the magic bytes are the real evidence, not Content-Type)
    head = meta.get("first_bytes")
    if not isinstance(head, bytes):
        errors["first_bytes"] = "first_bytes must be bytes"
    elif ext is not None and not head.startswith(_MAGIC[ext]):
        errors["first_bytes"] = "file signature does not match the file extension"

    # size_bytes: a real int; bool is a subclass of int so exclude it explicitly
    size = meta.get("size_bytes")
    if isinstance(size, bool) or not isinstance(size, int):
        errors["size_bytes"] = "size_bytes must be an integer"
    elif not 1 <= size <= MAX_BYTES:
        errors["size_bytes"] = f"size_bytes must be between 1 and {MAX_BYTES}"

    # matter_id
    matter = meta.get("matter_id")
    if not isinstance(matter, str) or not matter.isascii() or not _MATTER_RE.fullmatch(matter):
        errors["matter_id"] = "matter_id must look like MAT-2026-00042"

    if errors:
        raise ValidationError(errors)

    return CleanUpload(
        stored_name=secrets.token_hex(16) + "." + ext,  # never derived from the filename
        display_name=display,
        extension=ext,
        content_type=_CONTENT_TYPES[ext],
        size_bytes=size,
        matter_id=matter,
    )
