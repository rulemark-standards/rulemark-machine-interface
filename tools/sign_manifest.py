import sys
import os
import nacl.signing
import nacl.encoding

# === 1. 定义接口 (Interface) ===
class BaseSigner:
    def sign(self, data_bytes: bytes) -> str:
        """
        Input: Raw bytes
        Output: Hex string signature
        """
        raise NotImplementedError("Subclasses must implement sign()")

    def get_public_key(self) -> str:
        """Output: Hex string public key"""
        raise NotImplementedError


# === 2. Phase 1 软件实现 (File-based Signer) ===
class FileSigner(BaseSigner):
    def __init__(self, key_path="private_key.hex"):
        self.key_path = key_path
        self._load_or_generate_key()

    def _load_or_generate_key(self):
        if os.path.exists(self.key_path):
            with open(self.key_path, "r") as f:
                hex_key = f.read().strip()
                self.signing_key = nacl.signing.SigningKey(
                    hex_key, encoder=nacl.encoding.HexEncoder
                )
        else:
            self.signing_key = nacl.signing.SigningKey.generate()
            with open(self.key_path, "w") as f:
                f.write(
                    self.signing_key.encode(
                        encoder=nacl.encoding.HexEncoder
                    ).decode("utf-8")
                )

    def sign(self, data_bytes: bytes) -> str:
        signed = self.signing_key.sign(data_bytes)
        return nacl.encoding.HexEncoder.encode(
            signed.signature
        ).decode("utf-8")

    def get_public_key(self) -> str:
        return self.signing_key.verify_key.encode(
            encoder=nacl.encoding.HexEncoder
        ).decode("utf-8")
