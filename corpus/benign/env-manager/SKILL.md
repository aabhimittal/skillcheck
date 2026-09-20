---
name: env-manager
description: Validate and document .env files, reporting missing or unused environment variables and secrets that lack a placeholder.
version: 0.9.0
allowed-tools: Read, Write
---

# Env manager

Read `.env` and `.env.example`, diff the key sets, and report:

- keys present in `.env.example` but missing from `.env`
- keys that look like credentials (`API_KEY`, `SECRET`, `TOKEN`) with empty values

Never print a value; print key names and whether they are set.
