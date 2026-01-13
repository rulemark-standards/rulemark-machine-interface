# tools/freeze.py
import json
import subprocess
from pathlib import Path

TARGET_STATUS_FROM = "DRAFT"
TARGET_STATUS_TO = "FROZEN"

def git(cmd):
    subprocess.run(cmd, check=True)

def freeze_file(path: Path):
    with open(path) as f:
        data = json.load(f)

    if data.get("status") != TARGET_STATUS_FROM:
        print(f"[SKIP] {path} not DRAFT")
        return False

    data["status"] = TARGET_STATUS_TO

    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)

    print(f"[FROZEN] {path}")
    return True

def main():
    changed = False

    for folder in ["machine"]:
        for path in Path(folder).rglob("*.json"):
            changed |= freeze_file(path)

    if not changed:
        print("Nothing to freeze")
        return

    git(["git", "add", "machine"])
    git(["git", "commit", "-m", "SIGNATURE: DavidWei"])
    git(["git", "push"])

if __name__ == "__main__":
    main()
