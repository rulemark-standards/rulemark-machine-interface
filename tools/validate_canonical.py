import json
import sys
from pathlib import Path

import jsonschema
from jsonschema import validate

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "machine" / "canonical_record.schema.json"
MACHINE_DIR = ROOT / "machine"

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    if not SCHEMA_PATH.exists():
        print(f"[FATAL] Schema not found: {SCHEMA_PATH}")
        sys.exit(1)

    schema = load_json(SCHEMA_PATH)

    errors = 0

    for json_file in MACHINE_DIR.glob("*.json"):
        if json_file.name == "canonical_record.schema.json":
            continue

        try:
            data = load_json(json_file)
            validate(instance=data, schema=schema)
            print(f"[PASS] {json_file.name}")
        except jsonschema.exceptions.ValidationError as e:
            print(f"[FAIL] {json_file.name}")
            print(f"       → {e.message}")
            errors += 1

    if errors > 0:
        print(f"\n❌ Validation failed: {errors} file(s) invalid.")
        sys.exit(1)

    print("\n✅ All canonical records are valid.")
    sys.exit(0)

if __name__ == "__main__":
    main()
