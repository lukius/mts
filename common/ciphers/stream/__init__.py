from common.ciphers import Cipher
from common.tools.xor import ByteXOR


class StreamCipher(Cipher):
    
    def _xor_with_key(self, string):
        byte_count = len(string)
        xor_key = self._compute_key_bytes(byte_count)
        return ByteXOR(string, xor_key).value()
    
    def encrypt(self, plaintext):
        return self._xor_with_key(plaintext)
    
    def decrypt(self, ciphertext):
        return self._xor_with_key(ciphertext)
    
    def _compute_key_bytes(self):
        raise NotImplementedError