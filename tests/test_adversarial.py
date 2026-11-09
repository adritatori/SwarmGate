"""Messy / adversarial inputs for every decision the gateway makes.

Run:  python -m pytest -q
Each test tries to sneak something past one rule. All must be REJECTED
(or, for the audit log, DETECTED).
"""
import copy
import random

import pytest

from oor.audit import Anchor, AuditLog, entry_hash, verify_chain
from oor.gateway import Agent, Denied, Gateway
from oor.identity import KeyPair, Registry, RegistryError, issue_credential, normalize_scopes
from oor.world import World


def make(mode="external"):
    op = KeyPair()
    gw = Gateway(mode, World(random.Random(0)), op)
    a = Agent("alice", {"records:read", "spawn", "email:send"}, {"orchestrate", "worker"})
    b = Agent("bob", {"files:write"}, {"summarize"})
    gw.enroll(a)
    gw.enroll(b)
    return gw, op, a, b


# ----------------------------------------------------------- scope parsing
@pytest.mark.parametrize("bad", ["records:*", "*", "records:read ", " records:read", "Records:Read",
                                 "records:reаd",  # Cyrillic 'а'
                                 "records:read\x00", "records:read,email:send", "", None, 5, ["records:read"]])
def test_weird_scopes_rejected(bad):
    with pytest.raises(ValueError):
        normalize_scopes([bad])


# ------------------------------------------------------------- credentials
def test_forged_credential_wrong_signer():
    op, evil = KeyPair(), KeyPair()
    reg = Registry(op)
    subject = KeyPair()
    cred = issue_credential(evil, subject.pub_b, ["records:read"], [], "x")
    cred["body"]["issuer_id"] = op.id  # claim the operator signed it
    with pytest.raises(RegistryError):
        reg.register(cred)


def test_edited_credential_after_signing():
    op = KeyPair()
    reg = Registry(op)
    s = KeyPair()
    cred = issue_credential(op, s.pub_b, ["files:write"], [], "x")
    cred["body"]["scopes"] = ["files:write", "records:write"]
    with pytest.raises(RegistryError):
        reg.register(cred)


def test_subject_id_not_matching_key():
    op = KeyPair()
    reg = Registry(op)
    cred = issue_credential(op, KeyPair().pub_b, ["files:write"], [], "x")
    cred["body"]["subject_id"] = "agt_0000000000000000"
    cred["sig"] = op.sign(cred["body"])  # even re-signed by operator
    with pytest.raises(RegistryError):
        reg.register(cred)


def test_narrowing_enforced_even_if_issuer_skips_check():
    gw, op, a, _ = make()
    child = Agent("c", {"records:read", "records:write"}, {"worker"})
    cred = a.issue_child(child)  # issuer happily signs a superset
    with pytest.raises(RegistryError):
        gw.registry.register(cred)


def test_grandchild_cannot_regain_dropped_scope():
    gw, op, a, _ = make()
    c = Agent("c", {"spawn"}, {"worker"})
    gw.spawn(a.env("spawn"), c, a.issue_child(c))
    g = Agent("g", {"spawn", "records:read"}, {"worker"})
    with pytest.raises(Denied):
        gw.spawn(c.env("spawn"), g, c.issue_child(g))


def test_issuer_without_spawn_scope():
    gw, op, a, b = make()
    c = Agent("c", {"files:write"}, {"summarize"})
    with pytest.raises(Denied):
        gw.spawn(b.env("spawn"), c, b.issue_child(c))


def test_revoked_ancestor_revokes_descendants_and_blocks_new_spawns():
    gw, op, a, _ = make()
    c = Agent("c", {"records:read", "spawn"}, {"worker"})
    gw.spawn(a.env("spawn"), c, a.issue_child(c))
    gw.registry.revoke(a.id)
    with pytest.raises(Denied):
        gw.call_tool(c.env("tool", payload={"tool": "records_read", "args": {"record_id": "cust_0"}}))
    g = Agent("g", {"records:read"}, {"worker"})
    with pytest.raises(Denied):
        gw.spawn(c.env("spawn"), g, c.issue_child(g))


def test_fresh_key_self_copy_is_a_stranger():
    """An agent that 'copies itself' with a new key has no credential."""
    gw, op, a, _ = make()
    clone = Agent("alice", a.scopes, a.skills)
    with pytest.raises(Denied):
        gw.call_tool(clone.env("tool", payload={"tool": "records_read", "args": {"record_id": "cust_0"}}))


# -------------------------------------------------------------- envelopes
def test_claim_other_agents_id():
    gw, op, a, b = make()
    env = b.env("tool", payload={"tool": "records_read", "args": {"record_id": "cust_0"}}, claimed_id=a.id)
    with pytest.raises(Denied, match="bad signature"):
        gw.call_tool(env)


def test_claimed_scopes_ignored():
    gw, op, a, b = make()
    env = b.env("tool", payload={"tool": "records_read", "args": {"record_id": "cust_0"}},
                claimed_scopes=["records:read"])
    with pytest.raises(Denied, match="missing scope"):
        gw.call_tool(env)


def test_replay_and_replay_with_new_nonce():
    gw, op, a, b = make()
    env = a.env("send", to="bob", payload={"x": 1})
    gw.send(env)
    with pytest.raises(Denied, match="replayed"):
        gw.send(copy.deepcopy(env))
    e2 = copy.deepcopy(env)
    e2["body"]["nonce"] = "ffff"
    with pytest.raises(Denied, match="bad signature"):
        gw.send(e2)


def test_garbage_signature():
    gw, op, a, b = make()
    env = a.env("send", to="bob")
    for junk in ["", "!!!", "A" * 88, "AAAA"]:
        e = copy.deepcopy(env)
        e["sig"] = junk
        with pytest.raises(Denied):
            gw.send(e)


def test_name_squatting_and_unicode_lookalike():
    gw, op, a, b = make()
    with pytest.raises(Denied):
        gw.rename(b.env("rename", payload={"new_name": "alice"}))
    # Look-alike name IS allowed by the registry -> documented weakness.
    gw.rename(b.env("rename", payload={"new_name": "аlice"}))  # Cyrillic а
    assert gw.registry.names["аlice"] == b.id  # but it stays bound to bob's key


def test_card_cannot_claim_unregistered_skill():
    gw, op, a, b = make()
    with pytest.raises(Denied):
        gw.publish_card(b.env("card", payload={"name": "bob", "skills": ["summarize", "billing"]}))


# --------------------------------------------------------------- audit log
def _log(n=6):
    anc = Anchor()
    log = AuditLog(anc)
    for i in range(n):
        log.append({"i": i, "actor": "x"})
    return log, anc


def test_clean_chain_verifies():
    log, anc = _log()
    assert verify_chain(log.entries, anc)[0]


@pytest.mark.parametrize("attack", ["edit", "delete_middle", "truncate", "reorder", "swap_hash"])
def test_audit_tamper_detected(attack):
    log, anc = _log()
    es = copy.deepcopy(log.entries)
    if attack == "edit":
        es[2]["record"]["actor"] = "y"
    elif attack == "delete_middle":
        del es[3]
    elif attack == "truncate":
        es = es[:-1]
    elif attack == "reorder":
        es[1], es[2] = es[2], es[1]
    elif attack == "swap_hash":
        es[4]["hash"] = "f" * 64
    assert not verify_chain(es, anc)[0]


def test_full_rewrite_needs_anchor():
    log, anc = _log()
    kept = [e["record"] for e in log.entries[:-2]] + [{"i": 99, "actor": "fake"}] * 2
    forged, prev = [], "0" * 64
    for i, r in enumerate(kept):
        e = {"seq": i, "prev": prev, "record": r}
        e["hash"] = entry_hash(e)
        forged.append(e)
        prev = e["hash"]
    assert verify_chain(forged)[0] is True          # without anchor: fooled
    assert verify_chain(forged, anc)[0] is False    # with anchor: caught


# ------------------------------------------------------------------ taint
def test_taint_blocks_external_email_only():
    gw, op, a, b = make("external+taint")
    gw.send(b.env("result", to="alice", payload={"text": "hi"}))
    assert a.id in gw.tainted
    gw.call_tool(a.env("tool", payload={"tool": "email_send", "args": {"to": "t@corp.example", "body": "x"}}))
    for addr in ["x@evil.example", "x@corp.example.evil.com", "X@CORP.EXAMPLE.ru", "x@corp-example.com"]:
        with pytest.raises(Denied):
            gw.call_tool(a.env("tool", payload={"tool": "email_send", "args": {"to": addr, "body": "x"}}))


def test_self_mode_trusts_everything():
    """Sanity check that the baseline really is the weak one."""
    gw, op, a, b = make("self")
    env = b.env("tool", payload={"tool": "records_read", "args": {"record_id": "cust_0"}},
                claimed_scopes=["records:read"])
    assert gw.call_tool(env)["secret"].startswith("SECRET-")
