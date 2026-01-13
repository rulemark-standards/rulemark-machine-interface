# tools/clerk_bot.py
import json
import subprocess
import sys
from pathlib import Path

ALLOWED_STATUS = "DRAFT"
ALLOWED_DIRS = ["machine", "registry"]

def fail(msg):
    print(f"[CLERK BOT BLOCKED] {msg}")
    sys.exit(1)

def git(cmd):
    subprocess.run(cmd, check=True)

def validate_json(path: Path):
    with open(path) as f:
        data = json.load(f)

    if "status" not in data:
        fail(f"{path} missing status")

    if data["status"] != ALLOWED_STATUS:
        fail(f"{path} status must be DRAFT")

def main():
    if len(sys.argv) < 2:
        fail("No files provided")

    files = [Path(p) for p in sys.argv[1:]]

    for f in files:
        if not any(str(f).startswith(d) for d in ALLOWED_DIRS):
            fail(f"{f} not in allowed dirs")

        if f.suffix != ".json":
            fail(f"{f} not json")

        validate_json(f)

    git(["git", "add", *sys.argv[1:]])
    git(["git", "commit", "-m", "CLERK: submit DRAFT"])
    git(["git", "push"])

    print("CLERK BOT: DRAFT submitted")

if __name__ == "__main__":
    main()

