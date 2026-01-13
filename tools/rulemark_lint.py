
#!/usr/bin/env python3
import json
import sys
import os
import re

MAX_STRING_LEN = 80

REQUIRED_TOP_KEYS = {
    "canonical_id",
    "schema_version",
    "status",
    "machine_logic",
    "scope",
    "constraints",
}

ALLOWED_STATUS = {"DRAFT", "FROZEN"}

CANONICAL_ID_PATTERN = re.compile(r"^RM-(S|P)-[A-Z]+-\d{3}$")


def fail(msg: str):
    print(f"[RULEMARK LINT FAIL] {msg}")
    sys.exit(1)


def is_long_string(value):
    return isinstance(value, str) and len(value) > MAX_STRING_LEN


def scan_for_long_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            scan_for_long_strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            scan_for_long_strings(v, f"{path}[{i}]")
    else:
        if is_long_string(obj):
            fail(f"Natural language detected at {path} (>{MAX_STRING_LEN} chars)")


def validate_standard(data: dict):
    # 1. 顶层字段
    missing = REQUIRED_TOP_KEYS - data.keys()
    if missing:
        fail(f"Missing required keys: {missing}")

    # 2. canonical_id 规则
    cid = data["canonical_id"]
    if not CANONICAL_ID_PATTERN.match(cid):
        fail(f"Invalid canonical_id format: {cid}")

    # 3. status 合法性
    status = data["status"]
    if status not in ALLOWED_STATUS:
        fail(f"Invalid status: {status}")

    # 4. machine_logic 必须强硬
    ml = data["machine_logic"]
    if ml.get("allow_interpretation") is not False:
        fail("machine_logic.allow_interpretation must be false")
    if ml.get("enforce_strict_mode") is not True:
        fail("machine_logic.enforce_strict_mode must be true")

    # 5. scope 必须是 ENUM
    scope = data["scope"]
    if not isinstance(scope.get("applies_to"), list):
        fail("scope.applies_to must be array")
    if "excludes" in scope and not isinstance(scope["excludes"], list):
        fail("scope.excludes must be array")

    # 6. constraints 必须是布尔 / 枚举
    constraints = data["constraints"]
    for k, v in constraints.items():
        if isinstance(v, dict):
            continue
        if isinstance(v, bool):
            continue
        if isinstance(v, str) and len(v) <= 32:
            continue
        fail(f"Invalid constraint value type at constraints.{k}")

    # 7. 禁止自然语言
    scan_for_long_strings(data)

    # 8. FROZEN 必须有 freeze_receipt
    if status == "FROZEN":
        if "freeze_receipt" not in data:
            fail("FROZEN standard missing freeze_receipt")


def main():
    if len(sys.argv) < 2:
        fail("Usage: rulemark_lint.py <json files>")

    for filepath in sys.argv[1:]:
        if not filepath.endswith(".json"):
            continue

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            fail(f"Invalid JSON in {filepath}: {e}")

        validate_standard(data)
        print(f"[PASS] {filepath}")


if __name__ == "__main__":
    main()
