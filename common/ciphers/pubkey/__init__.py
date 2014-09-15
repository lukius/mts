from common.ciphers import Cipher
from common.tools.converters import BytesToInt, IntToBytes


class PublicKeyCipher(Cipher):
    
    def get_public_key(self):
        return self.public_key
    
    def encrypt(self, plaintext):
        return self._process_with(plaintext, self._encrypt)
    
    def decrypt(self, ciphertext):
        return self._process_with(ciphertext, self._decrypt)
        
    def _process_with(self, text, method):
        # Convert text to integer before encryption/decryption.
        integer = self._to_int(text)
        result = method(integer)
        # And convert back to byte string before returning.
        return self._from_int(result)
    
    def _to_int(self, byte_string):
        return BytesToInt(byte_string).value()
    
    def _from_int(self, integer):
        return IntToBytes(integer).value()
    
    def _encrypt(self, int_plaintext):
        raise NotImplementedError
        
    def _decrypt(self, int_ciphertext):
        raise NotImplementedError        