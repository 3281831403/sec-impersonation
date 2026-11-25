"""Impersonation session core for the security exercise.

A store is a plain dict with these fields:

    users: dict[str, dict]
        Each user record has an admin boolean and a permissions list.
    permissions: dict[str, list[str]]
        Current effective permissions. Missing entries fall back to the user
        record.
    sessions: dict[str, dict]
        Active and completed impersonation sessions keyed by session id.
    seq: int
        Optional counter used to allocate session ids.
    logs: list[dict]
        Optional audit trail.

A session is a plain dict with these fields:

    id: str
        Unique session id.
    actor: str
        The real operator who started the impersonation.
    subject: str
        The user being impersonated.
    started: float
        Start time in epoch seconds.
    expires: float
        Fixed end of the allowed window in epoch seconds.
    active: bool
        Whether impersonation is still in effect.
    actor_permissions: list[str]
        Snapshot of the operator permissions taken before impersonation.
    permissions: list[str]
        Effective permissions carried by the session.
    high_risk_actions: list[str]
        Actions that require confirmation during impersonation.

A policy is a plain dict with these fields:

    max_seconds: float
        Maximum lifetime of an impersonation session in seconds.
    admin_users: list[str]
        Optional names that must never be impersonated.
    allowed_actors: list[str]
        Optional allowlist of support operators.
    high_risk_actions: list[str]
        Optional action names that require confirmation.
    store: dict
        Optional default store used by impersonate_batch.

A batch request is a dict with these fields:

    id: str
        Caller supplied result key.
    actor: str
        Real operator.
    subject: str
        User to impersonate.
    store: dict
        Optional store for this request. A policy level store is used when
        the request does not carry one.
"""

from __future__ import annotations

from typing import Any

DEFAULT_HIGH_RISK = ("delete", "export", "grant_role", "change_password")
_SECONDS_PER_DAY = 24 * 60 * 60


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _permissions_for(store: dict, user: str) -> list[str]:
    current = store.get("permissions")
    if isinstance(current, dict) and user in current:
        return list(current[user])
    users = store.get("users")
    if isinstance(users, dict):
        record = users.get(user)
        if isinstance(record, dict):
            return list(record.get("permissions", []))
    return []


def _set_permissions(store: dict, user: str, permissions: list[str]) -> None:
    current = store.setdefault("permissions", {})
    if not isinstance(current, dict):
        current = {}
        store["permissions"] = current
    current[user] = list(permissions)


def _high_risk_actions(policy: dict) -> list[str]:
    configured = policy.get("high_risk_actions", DEFAULT_HIGH_RISK)
    if isinstance(configured, (list, tuple, set)):
        return [str(item) for item in configured]
    return list(DEFAULT_HIGH_RISK)


def _default_store(actor: str, subject: str) -> dict:
    users = {
        actor: {"admin": False, "permissions": []},
        subject: {"admin": False, "permissions": []},
    }
    return {"users": users, "permissions": {}, "sessions": {}, "seq": 0}


def _policy_admin(subject: str, policy: dict) -> bool:
    admins = policy.get("admin_users", ())
    return subject in admins if isinstance(admins, (list, tuple, set)) else False


def _store_admin(store: dict, subject: str) -> bool:
    users = store.get("users")
    if not isinstance(users, dict):
        return False
    record = users.get(subject)
    return bool(isinstance(record, dict) and record.get("admin", False))


def start(store: dict, actor: str, subject: str, now: float, policy: dict) -> dict:
    """Start an impersonation session and return it.

    The session records both identities, snapshots the operator permissions,
    replaces them with the subject permissions, and expires after the policy
    lifetime. Refuse blank identities, self impersonation, disallowed operators
    and administrator subjects.
    """
    if not isinstance(store, dict):
        raise ValueError("store must be a dict")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor is required")
    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("subject is required")
    if not _is_number(now):
        raise ValueError("now must be a number")
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")
    if not check_allowed(actor, subject, policy):
        raise ValueError("impersonation is not allowed")
    if _store_admin(store, subject):
        raise ValueError("impersonation is not allowed")

    max_seconds = policy.get("max_seconds")
    if not _is_number(max_seconds) or float(max_seconds) <= 0:
        raise ValueError("max_seconds must be positive")

    try:
        seq = int(store.get("seq", 0)) + 1
    except (TypeError, ValueError) as exc:
        raise ValueError("store seq must be an integer") from exc
    store["seq"] = seq
    session_id = f"imp-{seq}"

    permissions = _permissions_for(store, subject)
    session = {
        "id": session_id,
        "actor": actor,
        "subject": subject,
        "started": float(now),
        "expires": float(now) + float(max_seconds),
        "active": True,
        "actor_permissions": _permissions_for(store, actor),
        "permissions": permissions,
        "high_risk_actions": _high_risk_actions(policy),
    }
    store.setdefault("sessions", {})[session_id] = session
    _set_permissions(store, actor, permissions)
    return session


def check_allowed(actor: str, subject: str, policy: dict) -> bool:
    """Return whether actor may impersonate subject under policy.

    Blank identities, self impersonation, operators outside an explicit
    allowlist and administrator subjects are refused.
    """
    if not isinstance(actor, str) or not actor.strip():
        return False
    if not isinstance(subject, str) or not subject.strip():
        return False
    if actor == subject:
        return False
    if not isinstance(policy, dict):
        return False

    allowed = policy.get("allowed_actors")
    if allowed is not None and actor not in allowed:
        return False
    if _policy_admin(subject, policy):
        return False
    return True


def check_duration(session: dict, now: float, policy: dict) -> bool:
    """Return whether now is inside the fixed impersonation window.

    The deadline never moves. Sessions that are inactive, malformed or outside
    their start and expiry bounds are rejected.
    """
    if not isinstance(session, dict) or not _is_number(now):
        return False
    if not session.get("active", True):
        return False

    started = session.get("started")
    expires = session.get("expires")
    if not _is_number(started) or not _is_number(expires):
        return False
    if now < started:
        return False
    if now > expires:
        return False
    return True


def log_action(session: dict, action: str, now: float) -> dict:
    """Append an audit entry for an action taken during impersonation.

    The entry identifies the session, the impersonated user and the action.
    """
    if not isinstance(session, dict):
        raise ValueError("session must be a dict")
    if not isinstance(action, str) or not action.strip():
        raise ValueError("action is required")
    if not _is_number(now):
        raise ValueError("now must be a number")

    entry = {
        "session_id": session.get("id"),
        "actor": session.get("actor"),
        "subject": session.get("subject"),
        "action": action,
        "at": float(now),
    }
    session.setdefault("logs", []).append(entry)
    return dict(entry)


def needs_confirm(session: dict, action: str) -> bool:
    """Return whether action requires a second confirmation in this session."""
    if not isinstance(session, dict) or not isinstance(action, str):
        return False
    if not session.get("active", True):
        return False
    return action in session.get("high_risk_actions", ())


def end(store: dict, session: dict, now: float) -> dict:
    """End impersonation and restore the operator session.

    The session is marked inactive, the effective permissions are replaced by
    the pre-impersonation snapshot, and the store is updated immediately.
    """
    if not isinstance(store, dict):
        raise ValueError("store must be a dict")
    if not isinstance(session, dict):
        raise ValueError("session must be a dict")
    if not _is_number(now):
        raise ValueError("now must be a number")

    session_id = session.get("id")
    sessions = store.get("sessions")
    current = session
    if isinstance(sessions, dict) and session_id in sessions:
        current = sessions[session_id]

    if not current.get("active", False):
        return current

    operator = current.get("actor") or current.get("subject")
    restored = list(current.get("actor_permissions", []))
    current["permissions"] = list(restored)
    store.setdefault("permissions", {})[operator] = restored
    current["active"] = False
    current["ended"] = float(now)
    return current


def validate_session(session: dict) -> list[str]:
    """Return stable problem codes for a session, empty when it is healthy."""
    if not isinstance(session, dict):
        return ["invalid_session"]

    problems: list[str] = []
    if not session.get("actor"):
        problems.append("missing_actor")
    if not session.get("subject"):
        problems.append("missing_subject")

    if session.get("active", True):
        reference = session.get("now", session.get("checked_at"))
        expires = session.get("expires")
        if _is_number(reference) and _is_number(expires) and reference > expires:
            problems.append("expired")
    return problems


def impersonate_batch(requests: list[dict], policy: dict, now: float) -> dict:
    """Start a batch of impersonation requests and return results by id.

    A successful entry is {"ok": True, "session": session}; a refused entry is
    {"ok": False, "error": text}. Each request is handled independently.
    """
    if not isinstance(requests, (list, tuple)):
        raise ValueError("requests must be a list")
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")

    results: dict[str, dict] = {}
    for index, request in enumerate(requests):
        if not isinstance(request, dict):
            results[f"request-{index}"] = {"ok": False, "error": "request must be a dict"}
            continue
        request_id = request.get("id", f"request-{index}")
        if not isinstance(request_id, str) or not request_id:
            request_id = f"request-{index}"
        try:
            store = request.get("store")
            if not isinstance(store, dict):
                store = policy.get("store")
            if not isinstance(store, dict):
                store = _default_store(request.get("actor", ""), request.get("subject", ""))

            session = start(
                store,
                request["actor"],
                request["subject"],
                now,
                policy,
            )
            results[request_id] = {"ok": True, "session": session}
        except (KeyError, TypeError, ValueError) as exc:
            results[request_id] = {"ok": False, "error": str(exc)}
    return results