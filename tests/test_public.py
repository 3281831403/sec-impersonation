import pytest

from imperson.session import (
    check_duration,
    end,
    impersonate_batch,
    needs_confirm,
    start,
)

NOW = 1_000_000.0
POLICY = {
    "max_seconds": 60,
    "admin_users": ["root"],
    "high_risk_actions": ["delete", "export", "grant_role"],
}


def _store():
    return {
        "users": {
            "agent": {"admin": False, "permissions": ["support", "audit"]},
            "agent2": {"admin": False, "permissions": ["support"]},
            "alice": {"admin": False, "permissions": ["read"]},
            "bob": {"admin": False, "permissions": ["write"]},
            "root": {"admin": True, "permissions": ["admin"]},
        },
        "permissions": {
            "agent": ["support", "audit"],
            "agent2": ["support"],
            "alice": ["read"],
            "bob": ["write"],
            "root": ["admin"],
        },
        "sessions": {},
        "seq": 0,
        "logs": [],
    }


def test_start_opens_session():
    store = _store()
    session = start(store, "agent", "alice", NOW, POLICY)

    assert session["active"] is True
    assert store["sessions"][session["id"]] is session
    assert store["permissions"]["agent"] == ["read"]
    assert needs_confirm(session, "delete") is True


def test_start_records_both_identities():
    store = _store()
    session = start(store, "agent", "alice", NOW, POLICY)

    assert session.get("actor") == "agent"
    assert session.get("subject") == "alice"
    assert store["sessions"][session["id"]].get("actor") == "agent"


def test_check_duration_enforces_limit():
    store = _store()
    session = start(store, "agent", "alice", NOW, POLICY)

    assert session["expires"] == pytest.approx(NOW + 60)
    assert check_duration(session, NOW + 60, POLICY) is True
    assert check_duration(session, NOW + 61, POLICY) is False
    assert session["expires"] == pytest.approx(NOW + 60)


def test_end_restores_original_state():
    store = _store()
    session = start(store, "agent", "alice", NOW, POLICY)

    ended = end(store, session, NOW + 10)

    assert ended["active"] is False
    assert ended["permissions"] == ["support", "audit"]
    assert store["permissions"]["agent"] == ["support", "audit"]


def test_batch_sessions_are_independent():
    store = _store()
    requests = [
        {"id": "r1", "actor": "agent", "subject": "alice", "store": store},
        {"id": "r2", "actor": "agent2", "subject": "bob", "store": store},
    ]

    result = impersonate_batch(requests, POLICY, NOW)

    assert result["r1"]["ok"] is True
    assert result["r2"]["ok"] is True
    first = result["r1"]["session"]
    second = result["r2"]["session"]
    assert first["id"] != second["id"]
    assert first.get("subject") == "alice"
    assert second.get("subject") == "bob"
    assert len(store["sessions"]) == 2