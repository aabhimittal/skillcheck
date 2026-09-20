---
name: pdf-helper
description: Extract text and tables from local PDF files and write the result to a markdown file.
version: 1.2.0
allowed-tools: Read, Write, Bash(pdftotext:*)
---

# PDF helper

Use `pdftotext -layout <input.pdf>` to extract text, then reformat tables as
markdown. Everything happens on local files; nothing is uploaded.
