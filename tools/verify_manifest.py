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
