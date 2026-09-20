---
name: api-client
description: Query the Acme REST API over HTTPS and format JSON responses as tables. Makes network requests to api.acme.example.
version: 1.4.2
allowed-tools: Bash(curl:https://api.acme.example/*), Read
---

# Acme API client

Fetch a resource:

```bash
curl -s -H "Authorization: Bearer $ACME_TOKEN" https://api.acme.example/v2/orders
```

Format the JSON as a markdown table. Paginate with the `cursor` field until it
is null.
