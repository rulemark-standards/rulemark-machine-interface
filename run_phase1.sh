#!/bin/bash

# ==========================================
# RuleMark Phase 1: Zero-to-One Auto Script
# ==========================================

echo "🚀 RuleMark Phase 1 Initialization..."

# 1. 环境自检与依赖安装
echo "--- Step 1: Checking Environment ---"
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python3 not found."
    exit 1
fi

echo "📦 Installing PyNaCl (Crypto Lib)..."
pip3 install pynacl > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "⚠️  Warning: direct pip install failed. Trying to run without it or verify venv."
    # 继续尝试，假设用户可能已有环境
fi

# 2. 重建目录结构 (强制归零)
echo "--- Step 2: Scaffolding Directories ---"
mkdir -p machine
mkdir -p registry/manifests
mkdir -p tools
echo "✅ Directories ready."

# 3. 写入 Clerk (生成清单)
echo "--- Step 3: Writing Clerk Bot ---"
cat > tools/clerk_generate_manifest.py << 'EOF'
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
EOF

# 4. 写入 Signer (签名器 - 包含私钥生成)
echo "--- Step 4: Writing Signer ---"
cat > tools/sign_manifest.py << 'EOF'
import os, sys, nacl.signing, nacl.encoding

KEY_PATH = "private_key.hex"
MANIFEST_PATH = "registry/manifests/batch_manifest.json"
SIG_PATH = "registry/manifests/batch_manifest.sig"

def main():
    # 1. 搞定私钥
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "r") as f:
            hex_key = f.read().strip()
            signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
    else:
        signing_key = nacl.signing.SigningKey.generate()
        with open(KEY_PATH, "w") as f:
            f.write(signing_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'))
    
    # 2. 签名
    with open(MANIFEST_PATH, "rb") as f:
        data = f.read()
    signed = signing_key.sign(data)
    sig_hex = nacl.encoding.HexEncoder.encode(signed.signature).decode('utf-8')
    
    with open(SIG_PATH, "w") as f:
        f.write(sig_hex)
        
    pub_key = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    print(f"   [Signer] Signed successfully.")
    print(f"   [Signer] PUBLIC KEY: {pub_key}")
    
    # 自动保存公钥给 Verifier 用 (仅用于本次脚本自动演示)
    with open("temp_pub_key.txt", "w") as f:
        f.write(pub_key)

if __name__ == "__main__":
    main()
EOF

# 5. 写入 Verifier (验证器)
echo "--- Step 5: Writing Verifier ---"
cat > tools/verify_manifest.py << 'EOF'
import os, sys, nacl.signing, nacl.encoding, nacl.exceptions

def main():
    try:
        with open("temp_pub_key.txt", "r") as f:
            pub_key_hex = f.read().strip()
    except:
        print("   [Verifier] No Public Key found.")
        sys.exit(1)

    try:
        verify_key = nacl.signing.VerifyKey(pub_key_hex, encoder=nacl.encoding.HexEncoder)
        with open("registry/manifests/batch_manifest.json", "rb") as f:
            manifest_bytes = f.read()
        with open("registry/manifests/batch_manifest.sig", "r") as f:
            sig_hex = f.read().strip()
            
        verify_key.verify(manifest_bytes, nacl.encoding.HexEncoder.decode(sig_hex))
        print("   [Verifier] ✅ SUCCESS: Signature is VALID.")
    except Exception as e:
        print(f"   [Verifier] ❌ FAILED: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

# ==========================================
# 6. 执行全流程
# ==========================================
echo "--- 🚀 Executing Pipeline ---"

echo "> Running Clerk..."
python3 tools/clerk_generate_manifest.py

echo "> Running Signer..."
python3 tools/sign_manifest.py

echo "> Running Verifier..."
python3 tools/verify_manifest.py

if [ $? -eq 0 ]; then
    echo "=========================================="
    echo "✅ PHASE 1 COMPLETE: All systems operational."
    echo "=========================================="
else
    echo "❌ System Check Failed."
fi
