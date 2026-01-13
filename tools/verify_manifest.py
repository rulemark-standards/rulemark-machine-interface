import os, sys
import nacl.signing
import nacl.encoding
import nacl.exceptions

def main():
    pub_key_hex = os.environ.get("SIGNER_PUBLIC_KEY")
    if not pub_key_hex:
        print("❌ SIGNER_PUBLIC_KEY not provided to verifier.")
        sys.exit(1)

    try:
        verify_key = nacl.signing.VerifyKey(
            pub_key_hex,
            encoder=nacl.encoding.HexEncoder
        )

        with open("registry/manifests/batch_manifest.json", "rb") as f:
            manifest_bytes = f.read()

        with open("registry/manifests/batch_manifest.sig", "r") as f:
            sig_hex = f.read().strip()

        verify_key.verify(
            manifest_bytes,
            nacl.encoding.HexEncoder.decode(sig_hex)
        )

        print("✅ VERIFIED: Sovereign signature valid.")
        sys.exit(0)

    except nacl.exceptions.BadSignatureError:
        print("❌ INVALID SIGNATURE.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
