"""Part 2: one authorize() function, deny by default, first denial wins."""
from __future__ import annotations

from dataclasses import dataclass, field

_ROLE_ACTIONS = {
    "partner": frozenset({"read", "comment", "upload_version", "delete", "share_external"}),
    "associate": frozenset({"read", "comment", "upload_version"}),
    "paralegal": frozenset({"read", "upload_version"}),
    "client": frozenset({"read", "comment"}),
    "auditor": frozenset(),
}
_ACTIONS = frozenset({"read", "comment", "upload_version", "delete", "share_external"})


@dataclass(frozen=True)
class User:
    id: str
    role: str
    client_id: str | None = None
    matters: frozenset[str] = field(default_factory=frozenset)
    mfa: bool = False


@dataclass(frozen=True)
class Document:
    id: str
    client_id: str
    matter_id: str
    confidentiality: str = "normal"
    legal_hold: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _deny(reason: str) -> Decision:
    return Decision(False, reason)


def _decide(user: User | None, action: str, doc: Document) -> Decision:
    # 1. unauthenticated
    if user is None or not user.id:
        return _deny("unauthenticated")
    # 2. unknown_action (isinstance guard keeps unhashable junk from raising)
    if not isinstance(action, str) or action not in _ACTIONS:
        return _deny("unknown_action")
    # 3. unknown_role
    role = user.role
    if not isinstance(role, str) or role not in _ROLE_ACTIONS:
        return _deny("unknown_role")
    # 4. legal hold beats everything for delete
    if action == "delete" and doc.legal_hold:
        return _deny("legal_hold")
    # 5. role may never do this action
    if action not in _ROLE_ACTIONS[role]:
        return _deny("role_not_permitted")
    # 6. tenant isolation: exact comparison, no case folding, no stripping
    if role == "client" and (user.client_id is None or user.client_id != doc.client_id):
        return _deny("tenant_mismatch")
    # 7. staff must be assigned to the matter
    if role in ("associate", "paralegal") and doc.matter_id not in user.matters:
        return _deny("not_assigned")
    # 8. clients and paralegals never see non-normal documents
    normal = doc.confidentiality == "normal"
    if role in ("client", "paralegal") and not normal:
        return _deny("restricted")
    # 9. sensitive documents and external sharing need MFA this session
    if (not normal or action == "share_external") and user.mfa is not True:
        return _deny("mfa_required")
    return Decision(True, "ok")


def authorize(user: User | None, action: str, doc: Document) -> Decision:
    try:
        return _decide(user, action, doc)
    except Exception:  # fail closed (OWASP A10): an error is a denial, never a skipped check
        return _deny("error")


def visible_documents(user: User | None, docs: list[Document]) -> list[Document]:
    """Lists go through the same policy, so they cannot leak what authorize() would refuse."""
    return [d for d in docs if authorize(user, "read", d).allowed]
