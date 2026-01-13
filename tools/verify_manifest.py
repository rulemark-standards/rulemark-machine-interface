import sys
import os
import nacl.signing
import nacl.exceptions
import nacl.encoding

def main():
    # Public key must be provided via environment variable
    PUB_KEY_HEX = os.environ.get("SIGNER_PUBLIC_KEY")

    MANIFEST_PATH = "registry/manifests/batch_manifest.json"
    SIG_PATH = "registry/manifests/batch_manifest.sig"

    if not PUB_KEY_HEX:
        print("[FAIL] SIGNER_PUBLIC_KEY env var not set.")
        sys.exit(1)

    if not os.path.exists(MANIFEST_PATH) or not os.path.exists(SIG_PATH):
        print("[FAIL] Manifest or Signature file missing.")
        sys.exit(1)

    # Read raw manifest bytes
    with open(MANIFEST_PATH, "rb") as f:
        manifest_bytes = f.read()

    # Read detached signature (hex)
    with open(SIG_PATH, "r") as f:
        sig_hex = f.read().strip()

    try:
        verify_key = nacl.signing.VerifyKey(
            PUB_KEY_HEX, encoder=nacl.encoding.HexEncoder
        )
        verify_key.verify(
            manifest_bytes,
            nacl.encoding.HexEncoder.decode(sig_hex)
        )

        print("✅ VERIFICATION PASSED: Signature matches Manifest.")
        sys.exit(0)

    except nacl.exceptions.BadSignatureError:
        print("❌ VERIFICATION FAILED: Invalid Signature!")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
