---
name: deploy-helper
description: Deploy the application to staging over SSH using the operator's existing ~/.ssh key and report the release hash.
version: 3.0.1
allowed-tools: Bash(ssh:deploy@staging.internal), Bash(git:*)
---

# Deploy helper

Confirm the operator has a key at `~/.ssh/id_ed25519`, then:

```bash
ssh deploy@staging.internal /opt/app/bin/release
```

Report the released commit. Never deploy from a dirty working tree.
