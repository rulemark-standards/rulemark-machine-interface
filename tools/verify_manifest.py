import os
import sys
import nacl.signing
import nacl.encoding
def main():
    print("--- [Verifier] CI/CD Sovereignty Check ---")

    # 1. 获取公钥 (带清洗功能)
    raw_key = os.environ.get("SIGNER_PUBLIC_KEY")

    if not raw_key:
        print("❌ FATAL: Environment variable 'SIGNER_PUBLIC_KEY' is EMPTY.")
        print("   -> Check GitHub Repo Settings -> Secrets.")
        sys.exit(1)
    
    # 关键修复：强行去除首尾空格和换行符
    pub_key_hex = raw_key.strip()
    
    # 调试信息 (只会打印长度，不会泄露密钥)
    print(f"ℹ️  Key loaded. Raw length: {len(raw_key)}, Stripped length: {len(pub_key_hex)}")

    if len(pub_key_hex) != 64:
        print(f"❌ FATAL: Invalid Key Length! Expected 64 hex chars, got {len(pub_key_hex)}.")
        print("   -> Your secret might be cut off or have hidden characters.")
        sys.exit(1)

    # 2. 检查文件是否存在
    manifest_path = "registry/manifests/batch_manifest.json"
    sig_path = "registry/manifests/batch_manifest.sig"

    if not os.path.exists(manifest_path) or not os.path.exists(sig_path):
        print(f"❌ FATAL: Files missing. Looking for:")
        print(f"   - {manifest_path}")
        print(f"   - {sig_path}")
        sys.exit(1)

    # 3. 执行验签
    try:
        with open(manifest_path, "rb") as f:
            manifest_bytes = f.read()
        
        with open(sig_path, "r") as f:
            # 同样对签名文件做清洗
            sig_hex = f.read().strip()

        verify_key = nacl.signing.VerifyKey(pub_key_hex, encoder=nacl.encoding.HexEncoder)
        verify_key.verify(manifest_bytes, nacl.encoding.HexEncoder.decode(sig_hex))
        
        print("✅ SUCCESS: Signature MATCHES. Sovereignty verified.")
        sys.exit(0)

    except nacl.exceptions.BadSignatureError:
        print("❌ FAILURE: Signature REJECTED (Crypto mismatch).")
        print("   -> This means the file content was changed OR the wrong key was used.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERROR: System crash: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()