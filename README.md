# Out of Reach

Which multi-agent attacks still work when identity, permissions and audit logs are moved **out of the agents' reach** onto a gateway they cannot modify?

- 10 attacks × 3 enforcement modes × N seeds, all inside a Docker network with no internet.
- Start with **GUIDE.md**. It explains every file and every step.

Quick start (PowerShell, inside this folder):
```
docker compose build
docker compose run --rm lab python -m oor.egress_check
docker compose run --rm lab python -m pytest -q
docker compose run --rm lab
```
