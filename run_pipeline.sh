#!/bin/bash
set -e

echo "① Validate canonical records"
python tools/validate_canonical.py

echo "② Lint RuleMark structure"
python tools/rulemark_lint.py

echo "③ Generate batch manifest"
python tools/clerk_generate_manifest.py

echo "④ Sign manifest"
python tools/sign_manifest.py

echo "⑤ Verify manifest"
python tools/verify_manifest.py

echo "⑥ Freeze records"
python tools/freeze.py

echo "✓ RuleMark pipeline completed — FROZEN"
