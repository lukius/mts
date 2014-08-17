from Crypto.Cipher import AES as AESModule

from modes import ECB


class BlockCipher(object):

    def __init__(self, key):
        self.cipher = self._init_cipher(key)
        
    def _init_cipher(self, key):
        raise NotImplementedError
    
    def _default_mode(self):
        return ECB()
    
    def encrypt_block(self, block):
        return self.cipher.encrypt(block)    

    def decrypt_block(self, block):
        return self.cipher.decrypt(block)
    
    def encrypt(self, message, mode=None):
        if mode is None:
            mode = self._default_mode()
        return mode.encrypt_with_cipher(message, self)
        
    def decrypt(self, message, mode=None):
        if mode is None:
            mode = self._default_mode()
        return mode.decrypt_with_cipher(message, self)


class AES(BlockCipher):
    
    def _init_cipher(self, key):
        return AESModule.new(key)