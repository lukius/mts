from common.xor import HexXOR


class XORCipher(object):
    
    def __init__(self, key):
        self.key = key
        
    def _extend_key_for(self, plaintext):
        plaintext_length = len(plaintext)
        key_length = len(self.key)
        quotient, remainder = divmod(plaintext_length, key_length)
        return self.key*quotient + self.key[:remainder]
    
    def encrypt(self, plaintext):
        return self.value(plaintext)
    
    def decrypt(self, ciphertext):
        return self.value(ciphertext)
        
    def value(self, plaintext):
        extended_key = self._extend_key_for(plaintext)
        return HexXOR(extended_key, plaintext).value()