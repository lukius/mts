from common.ciphers import Cipher
from common.random.mt19937 import MersenneTwister
from common.xor import ByteXOR


class MersenneTwisterCipher(Cipher):
    
    def __init__(self, key):
        self.prng = MersenneTwister(seed=key)
        
    def _xor_with_key(self, string):
        byte_count = len(string)
        xor_key = self.prng.rand_bytes(byte_count)
        return ByteXOR(string, xor_key).value()
    
    def encrypt(self, plaintext):
        return self._xor_with_key(plaintext)
    
    def decrypt(self, ciphertext):
        return self._xor_with_key(ciphertext)