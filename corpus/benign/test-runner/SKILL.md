---
name: test-runner
description: Run the project test suite as a subprocess, parse failures, and summarise which tests regressed.
version: 1.1.0
allowed-tools: Bash(npm:test), Bash(pytest:*)
---

# Test runner

Detect the runner from the manifest, execute the suite, and summarise failures.
Python projects use `subprocess.run(["pytest", "-q"])`; Node projects use
`npm test`. Report the first failing assertion per file.
