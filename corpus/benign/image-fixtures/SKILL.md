---
name: image-fixtures
description: Generate and compare small PNG fixtures for visual regression tests.
version: 0.5.0
---

# Image fixtures

The 1x1 transparent PNG used as a placeholder is embedded here so tests do not
need a network fetch:

```
data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==
```

Compare rendered output against the fixture with a 0.1% pixel tolerance.
