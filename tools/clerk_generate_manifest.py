import os, json, hashlib, datetime, glob

MACHINE_DIR = "machine"
OUTPUT_FILE = "registry/manifests/batch_manifest.json"

def main():
    items = []
    # 模拟扫描 machine 目录
    files = glob.glob(os.path.join(MACHINE_DIR, "*.json"))
    if not files:
        print("   [Clerk] No files found in machine/. Creating dummy data...")
        # 自动生成一个测试文件
        dummy_path = os.path.join(MACHINE_DIR, "RM-S-TEST-001.json")
        with open(dummy_path, "w") as f:
            json.dump({"canonical_id": "RM-S-TEST-001", "status": "PASS", "version": "1.0"}, f)
        files = [dummy_path]

    for fpath in files:
        with open(fpath, "r") as f:
            data = json.load(f)
        if data.get("status") == "PASS":
            with open(fpath, "rb") as f:
                f_hash = "sha256:" + hashlib.sha256(f.read()).hexdigest()
            items.append({
                "canonical_id": data["canonical_id"],
                "file_hash": f_hash,
                "status": "PASS"
            })

    # 生成 Merkle Root (简化版)
    concat = "".join([i["file_hash"] for i in items]).encode("utf-8")
    merkle_root = "sha256:" + hashlib.sha256(concat).hexdigest()

    manifest = {
        "meta": {"type": "RULEMARK_BATCH_MANIFEST", "batch_id": "AUTO-001"},
        "consensus_target": {"merkle_root": merkle_root},
        "items": items
    }
    
    with open(OUTPUT_FILE, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"   [Clerk] Generated Manifest: {len(items)} items")

if __name__ == "__main__":
    main()
