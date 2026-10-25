# Security Policy

## Status
This repository is an **academic prototype** (ESIGELEC). It is not intended for production and receives no security support guarantees. All accounts and data are fictional; the demo password is public on purpose.

## Reporting a vulnerability
Please open a GitHub issue **without** exploit details or secrets, and ask for a private contact; or use GitHub's private vulnerability reporting if it is enabled on the repository. Include the affected file, the impact and reproduction steps with synthetic data only.

## Secrets
- Never commit `backend/.env`, API keys, JWT secrets, databases (`*.db`), logs, or screenshots of credentials. These paths are listed in `.gitignore`.
- `backend/.env.example` contains placeholders only.
- Tests use synthetic values containing `FAKE`; such lines carry a `gitleaks:allow` comment. Real secrets must never be allow-listed.
- CI runs Gitleaks on the full history of every push and pull request.
- If a real key is ever exposed: revoke and rotate it at the provider first, then remove it from history (e.g. `git filter-repo`) and force-update only after coordinating with every collaborator.

## Security model
See `docs/threat-model.md`. Key principle: the language model only proposes; deterministic backend code authorizes. Detection guards are heuristic and documented as such.
