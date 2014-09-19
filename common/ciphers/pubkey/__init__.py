from common.ciphers import Cipher
from common.tools.converters import BytesToInt, IntToBytes


class PublicKeyCipher(Cipher):
    
    def get_public_key(self):
        return self.public_key
    
    def encrypt(self, plaintext):
        return self._process_with(plaintext, self._encrypt)
    
    def decrypt(self, ciphertext):
        return self._process_with(ciphertext, self._decrypt)
    
    def int_encrypt(self, plaintext):
        return self._apply_method(plaintext, self._encrypt)
    
    def int_decrypt(self, ciphertext):
        return self._apply_method(ciphertext, self._decrypt)
        
    def _process_with(self, text, method):
        result = self._apply_method(text, method)
        # Convert to byte string before returning.
        return self._from_int(result)
    
    def _apply_method(self, method_input, method):
        input_type = type(method_input)
        if input_type == str:
            # Convert text to integer before encryption/decryption.
            method_input = self._to_int(method_input)
        elif input_type not in [int, long]:
            raise RuntimeError('invalid cipher input')
        return method(method_input)
    
    def _to_int(self, byte_string):
        return BytesToInt(byte_string).value()
    
    def _from_int(self, integer):
        return IntToBytes(integer).value()
    
    def _encrypt(self, int_plaintext):
        raise NotImplementedError
        
    def _decrypt(self, int_ciphertext):
        raise NotImplementedError        