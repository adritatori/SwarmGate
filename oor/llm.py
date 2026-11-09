"""Tiny Ollama client. Ollama runs the model locally (on your RTX 3050).

Every call is recorded in `self.trace` (prompt, reply, settings, timing,
token counts) so experiments can be re-analysed later without re-running.
"""
import time

import requests


class OllamaClient:
    def __init__(self, model="qwen2.5:3b", base_url="http://localhost:11434", timeout=120,
                 temperature=0.0):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = float(temperature)
        self.calls = 0
        self.trace = []   # one dict per call; caller drains it with pop_trace()

    def chat(self, prompt, seed=0, purpose=""):
        self.calls += 1
        t0 = time.perf_counter()
        r = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": self.temperature, "seed": seed},
            },
            timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        reply = data["message"]["content"]
        self.trace.append({
            "model": self.model, "temperature": self.temperature, "seed": seed, "purpose": purpose,
            "prompt": prompt, "reply": reply, "latency_s": round(time.perf_counter() - t0, 4),
            "prompt_tokens": data.get("prompt_eval_count"), "reply_tokens": data.get("eval_count"),
        })
        return reply

    def pop_trace(self):
        out, self.trace = self.trace, []
        return out


class FakeClient:
    """Offline stand-in with the same interface, for tests (no model needed).

    `responder(prompt, seed)` returns the reply text.
    """

    def __init__(self, responder, model="fake"):
        self.responder = responder
        self.model = model
        self.temperature = 0.0
        self.calls = 0
        self.trace = []

    def chat(self, prompt, seed=0, purpose=""):
        self.calls += 1
        reply = self.responder(prompt, seed)
        self.trace.append({"model": self.model, "temperature": 0.0, "seed": seed, "purpose": purpose,
                           "prompt": prompt, "reply": reply, "latency_s": 0.0,
                           "prompt_tokens": None, "reply_tokens": None})
        return reply

    def pop_trace(self):
        out, self.trace = self.trace, []
        return out
