"""Sandbox check: can this container reach the internet? It should NOT.

Exit code 0 = sandbox holds (everything blocked). Exit code 1 = a leak.
"""
import socket
import sys

PROBES = [
    ("DNS lookup example.com", lambda: socket.getaddrinfo("example.com", 443)),
    ("TCP 1.1.1.1:443", lambda: socket.create_connection(("1.1.1.1", 443), timeout=3).close()),
    ("TCP 8.8.8.8:53", lambda: socket.create_connection(("8.8.8.8", 53), timeout=3).close()),
    ("TCP huggingface.co:443", lambda: socket.create_connection(("huggingface.co", 443), timeout=3).close()),
]


def ollama_pull_probe():
    """Confused-deputy check: can the lab make the MODEL SERVER fetch from the
    internet for it? (Ollama's /api/pull downloads from a registry.)"""
    import os
    import requests
    url = os.environ.get("OLLAMA_URL")
    if not url:
        return "skip"
    try:
        r = requests.post(f"{url}/api/pull", json={"model": "all-minilm", "stream": False}, timeout=30)
    except requests.RequestException as e:
        raise OSError(f"ollama not reachable: {type(e).__name__}")
    if r.ok and "success" in r.text:
        return
    raise OSError(f"pull failed as expected: {r.status_code} {r.text[:80]}")


PROBES.append(("Ollama /api/pull via model server", ollama_pull_probe))


def main():
    socket.setdefaulttimeout(3)
    leaks = 0
    for name, probe in PROBES:
        try:
            if probe() == "skip":
                print(f"skipped  {name}  (no OLLAMA_URL set)")
                continue
            print(f"LEAK     {name}  <-- the sandbox can reach the outside!")
            leaks += 1
        except OSError as e:
            print(f"blocked  {name}  ({type(e).__name__})")
    print("\nSANDBOX HOLDS" if leaks == 0 else f"\n{leaks} LEAK(S) FOUND")
    sys.exit(0 if leaks == 0 else 1)


if __name__ == "__main__":
    main()
