"""Identity layer: key-bound agent IDs, lineage credentials, revocation.

Key ideas
- An agent's ID is a hash of its public key, NOT its name. Renaming changes
  nothing about who it is.
- Every credential is signed by its issuer (the operator, or a parent agent
  that spawned it). That chain of signatures is the agent's "lineage".
- A child can never hold a scope its parent does not hold ("capability
  narrowing"). The Registry re-checks this itself; it never trusts the issuer.
- Revoking an agent revokes everything it spawned.
"""
import base64
import hashlib
import json
import itertools

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# The only scopes that exist. Anything else (wildcards, odd casing, spaces,
# look-alike unicode) is rejected outright.
VALID_SCOPES = frozenset(
    {"records:read", "records:write", "email:send", "files:read", "files:write", "spawn", "refund:issue"}
)

_counter = itertools.count()


def canon(obj) -> bytes:
    """Canonical JSON so the same object always signs/hashes the same way."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


def agent_id_from_pub(pub_b: bytes) -> str:
    return "agt_" + hashlib.sha256(pub_b).hexdigest()[:16]


def normalize_scopes(scopes) -> frozenset:
    out = set()
    for s in scopes:
        if not isinstance(s, str) or s not in VALID_SCOPES:
            raise ValueError(f"invalid scope: {s!r}")
        out.add(s)
    return frozenset(out)


class KeyPair:
    def __init__(self):
        self._priv = Ed25519PrivateKey.generate()
        self.pub_b = self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.id = agent_id_from_pub(self.pub_b)

    def sign(self, obj) -> str:
        return b64(self._priv.sign(canon(obj)))


def verify_sig(pub_b: bytes, obj, sig: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub_b).verify(unb64(sig), canon(obj))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def issue_credential(issuer: KeyPair, subject_pub_b: bytes, scopes, skills, display_name: str):
    """Issuer signs a credential for a subject key. Narrowing is checked later
    by the Registry, so a buggy or malicious issuer cannot bypass it."""
    body = {
        "subject_id": agent_id_from_pub(subject_pub_b),
        "subject_pub": b64(subject_pub_b),
        "issuer_id": issuer.id,
        "scopes": sorted(scopes),  # validated by Registry
        "skills": sorted(skills),
        "display_name": display_name,
        "serial": next(_counter),
    }
    return {"body": body, "sig": issuer.sign(body)}


class RegistryError(Exception):
    pass


class Registry:
    """Lives inside the gateway. Agents cannot write to it directly."""

    def __init__(self, root: KeyPair):
        self.root_id = root.id
        self.root_pub = root.pub_b
        self.creds = {}      # agent_id -> credential body
        self.names = {}      # display name -> agent_id (unique among active agents)
        self.revoked = set()

    def _issuer_pub(self, issuer_id):
        if issuer_id == self.root_id:
            return self.root_pub
        if issuer_id in self.creds:
            return unb64(self.creds[issuer_id]["subject_pub"])
        raise RegistryError("unknown issuer")

    def register(self, cred):
        body, sig = cred.get("body"), cred.get("sig")
        if not isinstance(body, dict) or not isinstance(sig, str):
            raise RegistryError("malformed credential")
        try:
            scopes = normalize_scopes(body["scopes"])
            pub_b = unb64(body["subject_pub"])
        except (KeyError, ValueError, TypeError) as e:
            raise RegistryError(f"bad fields: {e}")
        if agent_id_from_pub(pub_b) != body.get("subject_id"):
            raise RegistryError("subject_id does not match key")
        issuer_id = body.get("issuer_id")
        if not verify_sig(self._issuer_pub(issuer_id), body, sig):
            raise RegistryError("bad signature")
        if issuer_id != self.root_id:
            if not self.is_active(issuer_id):
                raise RegistryError("issuer revoked or inactive")
            parent = self.creds[issuer_id]
            if "spawn" not in parent["scopes"]:
                raise RegistryError("issuer may not spawn")
            if not scopes <= frozenset(parent["scopes"]):
                raise RegistryError("child scopes exceed parent (narrowing violated)")
            if not set(body["skills"]) <= set(parent["skills"]) | {"worker"}:
                raise RegistryError("child skills exceed parent")
        if body["subject_id"] in self.creds:
            raise RegistryError("already registered")
        name = body["display_name"]
        if name in self.names and self.is_active(self.names[name]):
            raise RegistryError("name already held by an active agent")
        self.creds[body["subject_id"]] = body
        self.names[name] = body["subject_id"]
        return body["subject_id"]

    def lineage(self, agent_id):
        chain = []
        cur = agent_id
        while cur in self.creds:
            chain.append(cur)
            cur = self.creds[cur]["issuer_id"]
        chain.append(cur)  # root
        return chain

    def is_active(self, agent_id):
        if agent_id not in self.creds:
            return False
        return not any(a in self.revoked for a in self.lineage(agent_id))

    def revoke(self, agent_id):
        self.revoked.add(agent_id)

    def rename(self, agent_id, new_name):
        if new_name in self.names and self.names[new_name] != agent_id and self.is_active(self.names[new_name]):
            raise RegistryError("name already held by an active agent")
        old = self.creds[agent_id]["display_name"]
        self.names.pop(old, None)
        self.names[new_name] = agent_id
        self.creds[agent_id] = dict(self.creds[agent_id], display_name=new_name)
        return old
