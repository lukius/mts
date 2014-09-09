from Crypto.Cipher import AES as AESModule

from common.ciphers.block import BlockCipher
from common.ciphers.block.modes import RandomAccessCTR
from common.ciphers.block.string import BlockString
from common.tools.xor import ByteXOR


class AES(BlockCipher):
    
    def _init_cipher(self, key):
        return AESModule.new(key)
    
    
class RandomAccessAES(AES):
    
    def __init__(self, key):
        AES.__init__(self, key)
        self.keystream = str()
    
    def decrypt(self, ciphertext, nonce=0):
        mode = RandomAccessCTR(nonce=nonce)
        plaintext = AES.decrypt(self, ciphertext, mode)
        self.keystream += mode.get_keystream()
        return plaintext
    
    def encrypt(self, plaintext, nonce=0):
        mode = RandomAccessCTR(nonce=nonce)
        ciphertext = AES.encrypt(self, plaintext, mode)
        self.keystream += mode.get_keystream()
        return ciphertext
    
    def edit(self, ciphertext, offset, plaintext):
        if type(ciphertext) is BlockString:
            ciphertext = ciphertext.bytes()
        length = len(plaintext)
        key_bytes = self.keystream[offset:offset+length]
        new_bytes = ByteXOR(plaintext, key_bytes).value()
        new_ciphertext = ciphertext[:offset] + new_bytes +\
                         ciphertext[offset+length:]
        return BlockString(new_ciphertext)