import os
import sys
import nacl.signing
import nacl.encoding
import nacl.exceptions

def main():
    print("--- [Verifier] Starting System Check ---")

    # 强制从 CI 环境变量读取
    pub_key_hex = os.environ.get("SIGNER_PUBLIC_KEY")

    if not pub_key_hex:
        print("❌ FATAL: Environment variable 'SIGNER_PUBLIC_KEY' is MISSING or EMPTY.")
        sys.exit(1)

    print(f"✅ Key loaded from Environment (Length: {len(pub_key_hex)})")

    manifest_path = "registry/manifests/batch_manifest.json"
    sig_path = "registry/manifests/batch_manifest.sig"

    if not os.path.exists(manifest_path) or not os.path.exists(sig_path):
        print("❌ FATAL: Manifest or Signature file is missing.")
        sys.exit(1)

    try:
        with open(manifest_path, "rb") as f:
            manifest_bytes = f.read()

        with open(sig_path, "r") as f:
            sig_hex = f.read().strip()

        verify_key = nacl.signing.VerifyKey(
            pub_key_hex,
            encoder=nacl.encoding.HexEncoder
        )

        verify_key.verify(
            manifest_bytes,
            nacl.encoding.HexEncoder.decode(sig_hex)
        )

        print("✅ SUCCESS: Sovereignty Verified.")
        sys.exit(0)

    except nacl.exceptions.BadSignatureError:
        print("❌ FAILURE: Signature INVALID.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
