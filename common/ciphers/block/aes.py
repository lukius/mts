from Crypto.Cipher import AES as AESModule

from common.ciphers.block import BlockCipher


class AES(BlockCipher):
    
    def _init_cipher(self, key):
        return AESModule.new(key)