---
name: log-triage
description: Search application logs for error patterns and summarise the top failures by frequency and first occurrence.
version: 1.0.0
allowed-tools: Bash(rg:*), Read
---

# Log triage

Search with ripgrep, group by normalised message, and report counts. Redact
anything matching a credential pattern before including a sample line.
