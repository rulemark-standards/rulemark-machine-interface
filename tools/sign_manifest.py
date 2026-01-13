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
