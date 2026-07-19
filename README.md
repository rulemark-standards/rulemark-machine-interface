# RuleMark Machine Interface

Automation and verification tools for RuleMark canonical records. Machine
output supports publication, discovery, and verification; it does not replace
the frozen PDF.

This repository is an automation workspace, not a second canonical archive.
Its registry files are derived mirrors. Only the Canonical Archive may define
the registered frozen set.

## Publishing integrity gate

Read the canonical
[Publishing Integrity Policy](https://github.com/rulemark-standards/rulemark-canonical-archive/blob/main/docs/PUBLISHING-INTEGRITY-POLICY.md)
before publishing or modifying a standard.

The gate checks PDF identity, filenames, SHA-256, bytes, pages, signed data,
Canonical Archive metadata, RuleMark Web source metadata, public Registry JSON,
Machine JSON, human pages, and downloads. Any mismatch exits non-zero and must
block publication.

### Local check

With the four repositories checked out as sibling directories:

```bash
python3 -m pip install pypdf
python3 scripts/verify_release.py \
  --canonical-dir ../rulemark-canonical-archive \
  --records-dir ../rulemark-records \
  --machine-dir . \
  --web-dir ../rulemark-web
```

Add `--online` after deployment to verify the public site and Records URLs:

```bash
python3 scripts/verify_release.py \
  --canonical-dir ../rulemark-canonical-archive \
  --records-dir ../rulemark-records \
  --machine-dir . \
  --web-dir ../rulemark-web \
  --online
```

### Release rule

Do not bypass a red gate. Do not modify a frozen PDF to make a check pass.
Resolve the conflicting source and preserve signed historical evidence.

## Existing signature pipeline

The existing RSSA signature workflow remains available in
`.github/workflows/rulemark-pipeline.yml`. The integrity gate is additive: a
valid manifest signature does not prove that public PDFs and website metadata
agree.
