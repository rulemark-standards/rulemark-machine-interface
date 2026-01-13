import json
import sys
import glob

def fail(msg):
    print(f"[LINT FAIL] {msg}")
    sys.exit(1)

for path in glob.glob("machine/*.json"):
    with open(path) as f:
        data = json.load(f)

    if "canonical_id" not in data:
        fail(f"{path} missing canonical_id")

    if data.get("status") not in ["DRAFT", "FROZEN"]:
        fail(f"{path} invalid status")

    for k, v in data.get("constraints", {}).items():
        if isinstance(v, str) and len(v) > 80:
            fail(f"{path} constraint {k} too verbose")

print("[LINT PASS]")
