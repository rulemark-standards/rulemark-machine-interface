import shutil
import sys
import os

SRC = "draft_box"
DST = "machine"

if not os.path.exists(SRC):
    print("[CLERK] No draft_box, skipping")
    sys.exit(0)

for f in os.listdir(SRC):
    if f.endswith(".json"):
        shutil.copy(f"{SRC}/{f}", f"{DST}/{f}")
        print(f"[CLERK] copied {f}")

print("[CLERK] done")
