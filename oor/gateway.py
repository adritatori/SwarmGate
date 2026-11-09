"""The gateway: every message, tool call, card, rename and spawn passes here.

Three modes (the independent variable of the experiment):

  self            Agents enforce security themselves. The gateway just
                  forwards. Identity = whatever name/ID the sender claims.
                  Permissions = whatever scopes the sender claims. Logs are
                  written by the agents and the agents can edit them.
                  (This is how many multi-agent setups work today.)

  external        A reference monitor the agents cannot modify. It verifies
                  signatures against the Registry, takes scopes from the
                  credential (never from the message), blocks replays,
                  enforces unique names, and writes its own hash-chained
                  audit log anchored off-host.

  external+taint  'external' plus a provenance rule: once an agent has read a
                  message from a peer that is not at least as privileged as
                  itself, its high-risk actions (email outside the company,
                  record writes) are held for human approval (= blocked here).
"""
import secrets
import time

from .audit import Anchor, AuditLog
from .identity import KeyPair, Registry, RegistryError, issue_credential
from .world import TOOL_SCOPE, World, is_external

MODES = ("self", "external", "external+taint")


class Denied(Exception):
    pass


class Agent:
    """An agent's own side: its key, its name, what it believes it may do."""

    def __init__(self, name, scopes, skills):
        self.kp = KeyPair()
        self.id = self.kp.id
        self.name = name
        self.scopes = set(scopes)
        self.skills = set(skills)
        self.cred = None

    def env(self, kind, to=None, payload=None, claimed_scopes=None, claimed_id=None, claimed_name=None):
        body = {
            "from_id": claimed_id or self.id,
            "from_name": claimed_name or self.name,
            "claimed_scopes": sorted(claimed_scopes if claimed_scopes is not None else self.scopes),
            "kind": kind,
            "to": to,
            "payload": payload or {},
            "nonce": secrets.token_hex(8),
        }
        return {"body": body, "sig": self.kp.sign(body)}

    def issue_child(self, child: "Agent"):
        return issue_credential(self.kp, child.kp.pub_b, child.scopes, child.skills, child.name)


class Gateway:
    def __init__(self, mode: str, world: World, operator: KeyPair):
        assert mode in MODES, mode
        self.mode = mode
        self.world = world
        self.operator = operator
        self.registry = Registry(operator)
        self.anchor = Anchor()
        self.audit = AuditLog(self.anchor)
        self.inbox = {}          # agent_id -> list of message bodies
        self.directory = {}      # card name -> {"agent_id", "card"}
        self.agents = {}         # agent_id -> Agent (for delivery only)
        self.agent_logs = {}     # self mode: name -> list (agent-writable!)
        self.seen_nonces = set()
        self.tainted = set()
        self.timing = []         # seconds spent in checks per request

    @property
    def external(self):
        return self.mode != "self"

    # ---------------------------------------------------------------- setup
    def enroll(self, agent: Agent):
        """Operator onboarding (not an agent action)."""
        if self.external:
            agent.cred = issue_credential(self.operator, agent.kp.pub_b, agent.scopes, agent.skills, agent.name)
            self.registry.register(agent.cred)
        self.agents[agent.id] = agent
        self.inbox.setdefault(agent.id, [])

    # ------------------------------------------------------------- checking
    def _check(self, env):
        """External modes: authenticate an envelope. Returns sender body."""
        t0 = time.perf_counter()
        body, sig = env["body"], env["sig"]
        aid = body["from_id"]
        try:
            if not self.registry.is_active(aid):
                raise Denied("sender not registered or revoked")
            from .identity import unb64, verify_sig
            pub = unb64(self.registry.creds[aid]["subject_pub"])
            if not verify_sig(pub, body, sig):
                raise Denied("bad signature")
            if body["nonce"] in self.seen_nonces:
                raise Denied("replayed message")
            self.seen_nonces.add(body["nonce"])
            return self.registry.creds[aid]
        finally:
            self.timing.append(time.perf_counter() - t0)

    def _log(self, env, action, outcome, extra=None):
        b = env["body"]
        rec = {"action": action, "outcome": outcome, **(extra or {})}
        if self.external:
            aid = b["from_id"]
            cred = self.registry.creds.get(aid, {})
            rec.update(actor_id=aid, actor_name=cred.get("display_name"),
                       lineage=self.registry.lineage(aid) if aid in self.registry.creds else None)
            self.audit.append(rec)
        else:
            rec.update(actor_id=b["from_id"], actor_name=b["from_name"])
            self.agent_logs.setdefault(b["from_name"], []).append(rec)

    def _guard(self, env, action):
        """Run the external check and log denials. Returns credential or None (self mode)."""
        if not self.external:
            return None
        try:
            return self._check(env)
        except Denied as d:
            self._log(env, action, f"denied: {d}")
            raise

    # ---------------------------------------------------------------- cards
    def publish_card(self, env):
        cred = self._guard(env, "publish_card")
        card = env["body"]["payload"]
        if self.external:
            if card["name"] != cred["display_name"]:
                self._log(env, "publish_card", "denied: card name != registered name")
                raise Denied("card name != registered name")
            if not set(card.get("skills", [])) <= set(cred["skills"]):
                self._log(env, "publish_card", "denied: card claims unregistered skills")
                raise Denied("card claims unregistered skills")
        self.directory[card["name"]] = {"agent_id": env["body"]["from_id"], "card": card}
        self._log(env, "publish_card", "ok", {"card_name": card["name"]})

    def cards_for(self, skill):
        """What an orchestrator gets when it asks 'who can do <skill>?'"""
        out = []
        for name, entry in self.directory.items():
            if self.external:
                aid = entry["agent_id"]
                if not self.registry.is_active(aid) or skill not in self.registry.creds[aid]["skills"]:
                    continue
                # Description is untrusted text; skills come from the credential.
                out.append({"name": name, "description": entry["card"].get("description", ""),
                            "skills": self.registry.creds[aid]["skills"]})
            else:
                out.append(dict(entry["card"]))
        return out

    def resolve(self, name):
        if self.external:
            aid = self.registry.names.get(name)
            return aid if aid and self.registry.is_active(aid) else None
        entry = self.directory.get(name)
        return entry["agent_id"] if entry else None

    # ------------------------------------------------------------- messages
    def send(self, env):
        cred = self._guard(env, "send")
        b = env["body"]
        to_id = self.resolve(b["to"])
        if to_id is None:
            self._log(env, "send", "denied: unknown recipient", {"to": b["to"]})
            raise Denied("unknown recipient")
        msg = {"from_id": b["from_id"], "from_name": cred["display_name"] if cred else b["from_name"],
               "kind": b["kind"], "payload": b["payload"], "_env": env}
        self.inbox[to_id].append(msg)
        if self.mode == "external+taint":
            rcpt = self.registry.creds[to_id]
            if not set(rcpt["scopes"]) <= set(cred["scopes"]):
                self.tainted.add(to_id)
        self._log(env, "send", "ok", {"to": b["to"], "to_id": to_id, "kind": b["kind"]})
        return to_id

    def replay_raw(self, env, to_id):
        """Attacker re-injects a captured envelope onto the wire."""
        try:
            cred = self._guard(env, "send")
        except Denied:
            raise
        b = env["body"]
        self.inbox[to_id].append({"from_id": b["from_id"],
                                  "from_name": cred["display_name"] if cred else b["from_name"],
                                  "kind": b["kind"], "payload": b["payload"], "_env": env})

    # ---------------------------------------------------------------- tools
    def call_tool(self, env):
        cred = self._guard(env, "tool")
        b = env["body"]
        tool, args = b["payload"]["tool"], b["payload"].get("args", {})
        need = TOOL_SCOPE[tool]
        held = set(cred["scopes"]) if cred else set(b["claimed_scopes"])
        extra = {"tool": tool, "args": args}
        if need not in held:
            self._log(env, "tool", f"denied: missing scope {need}", extra)
            raise Denied(f"missing scope {need}")
        if self.mode == "external+taint" and b["from_id"] in self.tainted:
            risky = (tool == "records_write") or (tool == "email_send" and is_external(args.get("to", "")))
            if risky:
                self._log(env, "tool", "held: needs human approval (tainted context)", extra)
                raise Denied("held for human approval (tainted context)")
        if tool == "email_send":
            result = self.world.email_send(b["from_id"], args["to"], args["body"])
        else:
            result = getattr(self.world, tool)(**args)
        self._log(env, "tool", "ok", extra)
        return result

    # --------------------------------------------------------- rename/spawn
    def rename(self, env):
        cred = self._guard(env, "rename")
        new = env["body"]["payload"]["new_name"]
        aid = env["body"]["from_id"]
        if self.external:
            try:
                old = self.registry.rename(aid, new)
            except RegistryError as e:
                self._log(env, "rename", f"denied: {e}", {"new_name": new})
                raise Denied(str(e))
            for name, entry in list(self.directory.items()):
                if entry["agent_id"] == aid:
                    self.directory[new] = dict(entry, card=dict(entry["card"], name=new))
                    del self.directory[name]
            self._log(env, "rename", "ok", {"old_name": old, "new_name": new})
        else:
            self._log(env, "rename", "ok", {"old_name": env["body"]["from_name"], "new_name": new})
        self.agents[aid].name = new

    def spawn(self, env, child: Agent, child_cred=None):
        parent = self._guard(env, "spawn")
        if self.external:
            if "spawn" not in parent["scopes"]:
                self._log(env, "spawn", "denied: missing scope spawn")
                raise Denied("missing scope spawn")
            try:
                self.registry.register(child_cred)
            except RegistryError as e:
                self._log(env, "spawn", f"denied: {e}", {"child_scopes": sorted(child.scopes)})
                raise Denied(str(e))
            child.cred = child_cred
        else:
            if "spawn" not in env["body"]["claimed_scopes"]:
                raise Denied("missing scope spawn")
        self.agents[child.id] = child
        self.inbox.setdefault(child.id, [])
        self._log(env, "spawn", "ok", {"child_id": child.id, "child_name": child.name,
                                        "child_scopes": sorted(child.scopes)})

    # ------------------------------------------------------- investigator
    def investigator_records(self):
        """What an auditor reads after the fact."""
        if self.external:
            return [e["record"] for e in self.audit.entries]
        return [r for logs in self.agent_logs.values() for r in logs]
