#!/bin/bash
set -e

echo "① Validate canonical records"
python3 tools/validate_canonical.py

echo "② Lint RuleMark structure"
python3 tools/rulemark_lint.py

echo "③ Generate batch manifest"
python3 tools/clerk_generate_manifest.py

echo "④ Sign manifest"
python3 tools/sign_manifest.py

echo "⑤ Verify manifest"
python3 tools/verify_manifest.py

echo "⑥ Freeze records"
python3 tools/freeze.py

echo "✓ RuleMark pipeline completed — FROZEN"
