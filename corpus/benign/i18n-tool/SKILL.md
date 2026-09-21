---
name: i18n-tool
description: Audit translation bundles for missing keys and check right-to-left strings render with the correct bidirectional marks.
version: 1.2.0
---

# i18n tool

Right-to-left locales need explicit marks around interpolated Latin text, or
the punctuation reorders. A correctly marked Arabic string looks like this:

```
"greeting": "‏مرحبا {name}‎"
```

Flag any RTL bundle whose interpolations lack the surrounding marks.
