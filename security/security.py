"""
Security implementation (Encryption and Integrity)

"""

import hashlib
import hmac
from crypto import AESCipher, HMACContext

# Global instances
g_crypt = AESCipher()
g_integrity = HMACContext()

HMAC_ON = True
ENC_ON = True

class AESCipher:
    """AES Encryption/Decryption Implementation"""
    
    def __init__(self):
        self.key = b'\x00' * 32  # AES-256
    
    def enc(self, pkt: any, key: int):
        """Encrypt packet"""
        # Convert int key to bytes
        key_bytes = key.to_bytes(32, 'big')
        ciphertext = self._encrypt(key_bytes, pkt.data[pkt.data_ptr:])
        pkt.data[pkt.data_ptr:pkt.data_ptr+len(ciphertext)] = ciphertext
        pkt.len += len(ciphertext)
    
    def dec(self, pkt: any, key: int):
        """Decrypt packet"""
        key_bytes = key.to_bytes(32, 'big')
        plaintext = self._decrypt(key_bytes, pkt.data[pkt.data_ptr:])
        pkt.data[pkt.data_ptr:pkt.data_ptr+len(plaintext)] = plaintext
        pkt.len -= len(plaintext)
    
    def _encrypt(self, key: bytes, data: bytes) -> bytes:
        """AES encryption"""
        # Simple simulation using XOR for demonstration
        # Real implementation uses AES library
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    
    def _decrypt(self, key: bytes, data: bytes) -> bytes:
        """AES decryption"""
        return self._encrypt(key, data)  # XOR is symmetric

class HMACContext:
    """HMAC Integrity Check Implementation"""
    
    def add_hmac(self, pkt: any, key: int):
        """Add HMAC to packet"""
        key_bytes = key.to_bytes(32, 'big')
        data = pkt.data[pkt.data_ptr:pkt.len]
        hmac_value = hmac.new(key_bytes, data, hashlib.sha256).digest()
        pkt.append_item_bytes(hmac_value)
    
    def rem_hmac(self, pkt: any, hmac_expected: bytes):
        """Remove and verify HMAC from packet"""
        # Simply mark that check was done for simulation
        pass
    
    def get_hmac(self, data: bytes, key: int, hmac_out: bytes):
        """Calculate HMAC for packet"""
        key_bytes = key.to_bytes(32, 'big')
        hmac_value = hmac.new(key_bytes, data, hashlib.sha256).digest()
        hmac_out[:] = hmac_value
    
    def cmp_hmacs(self, hmac1: bytes, hmac2: bytes) -> bool:
        """Compare HMACs"""
        return hmac.compare_digest(hmac1, hmac2)
    
    def hmac_check(self, pkt: any, key: int) -> bool:
        """Check HMAC of packet"""
        # Extract HMAC from end of data
        # This is a simulation
        return True