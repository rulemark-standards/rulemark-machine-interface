import os
import sys
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

MANIFEST_PATH = "registry/manifests/batch_manifest.json"
SIG_PATH = "registry/manifests/batch_manifest.sig"

def main():
    pub_key_hex = os.getenv("SIGNER_PUBLIC_KEY")
    if not pub_key_hex:
        print("[Verifier] ❌ SIGNER_PUBLIC_KEY not found in environment.")
        sys.exit(1)

    try:
        verify_key = VerifyKey(pub_key_hex, encoder=HexEncoder)

        with open(MANIFEST_PATH, "rb") as f:
            manifest_bytes = f.read()

        with open(SIG_PATH, "r") as f:
            sig_hex = f.read().strip()

        verify_key.verify(manifest_bytes, bytes.fromhex(sig_hex))
        print("[Verifier] ✅ VERIFIED: Sovereign signature valid.")

    except BadSignatureError:
        print("[Verifier] ❌ INVALID SIGNATURE.")
        sys.exit(1)
    except Exception as e:
        print(f"[Verifier] ❌ ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
