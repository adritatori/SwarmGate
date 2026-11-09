"""Gateway-side audit trail: append-only, hash-chained, with an external anchor.

Each entry stores the hash of the entry before it. Changing or deleting any
entry breaks every hash after it.

Weak spot (tested in tests/): someone who can rewrite the WHOLE file can
recompute every hash and make a consistent fake chain. That is why the
gateway also sends the latest head hash + length to an "anchor" the agents
cannot reach (in real life: a ticket, a separate server, an email).
"""
import hashlib
import json

from .identity import canon

GENESIS = "0" * 64


def entry_hash(entry_wo_hash) -> str:
    return hashlib.sha256(canon(entry_wo_hash)).hexdigest()


class Anchor:
    """Stands in for an off-host copy of the head hash."""

    def __init__(self):
        self.head = GENESIS
        self.length = 0

    def update(self, head, length):
        self.head, self.length = head, length


class AuditLog:
    def __init__(self, anchor: Anchor | None = None):
        self.entries = []
        self.head = GENESIS
        self.anchor = anchor

    def append(self, record: dict):
        e = {"seq": len(self.entries), "prev": self.head, "record": record}
        e["hash"] = entry_hash(e)
        self.entries.append(e)
        self.head = e["hash"]
        if self.anchor:
            self.anchor.update(self.head, len(self.entries))
        return e

    def dump_jsonl(self, path):
        with open(path, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(json.dumps(e) + "\n")


def verify_chain(entries, anchor: Anchor | None = None):
    """Return (ok, reason)."""
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            return False, f"bad seq at {i}"
        if e.get("prev") != prev:
            return False, f"broken link at {i}"
        body = {k: v for k, v in e.items() if k != "hash"}
        if entry_hash(body) != e.get("hash"):
            return False, f"hash mismatch at {i}"
        prev = e["hash"]
    if anchor is not None:
        if len(entries) != anchor.length:
            return False, f"length {len(entries)} != anchored {anchor.length}"
        if prev != anchor.head:
            return False, "head does not match anchor"
    return True, "ok"
