from string import BlockString

from common.converters import BytesToHex, HexToBytes
from common.padders import PKCS7Padder, PKCS7Unpadder
from common.xor import HexXOR


class BlockCipherMode(object):
    
    DEFAULT_BLOCK_SIZE = 16

    @classmethod                  
    def name(cls):
        return cls.__name__

    def __init__(self, block_size=None):
        self.block_size = self.DEFAULT_BLOCK_SIZE if block_size is None\
                          else block_size 
    
    def _is_last_block(self, index):
        return index == self.block_string.block_count()-1
    
    def _iterate_blocks(self, callback):
        for index, block in enumerate(self.block_string): 
            callback(index, block)

    def _iterate_blocks_with(self, block_string, cipher, callback):
        self.result = BlockString(block_size=self.block_size)
        self.cipher = cipher
        self.block_string = block_string
        self._iterate_blocks(callback)
        return self.result

    def _block_encryption_callback(self, message, cipher):
        raise NotImplementedError
    
    def _block_decryption_callback(self, message, cipher):
        raise NotImplementedError

    def encrypt_with_cipher(self, plaintext, cipher):
        block_string = BlockString(plaintext, self.block_size)
        return self._iterate_blocks_with(block_string, cipher,
                                         self._block_encryption_callback)
    
    def decrypt_with_cipher(self, ciphertext, cipher):
        if type(ciphertext) != BlockString:
            ciphertext = BlockString(ciphertext, self.block_size)
        return self._iterate_blocks_with(ciphertext, cipher,
                                         self._block_decryption_callback)


class ECB(BlockCipherMode):
    
    def _block_encryption_callback(self, index, block):
        # If block size is OK, it won't be padded.
        block = PKCS7Padder(block).value(self.block_size)
        self.result += self.cipher.encrypt_block(block)
    
    def _block_decryption_callback(self, index, block):
        plaintext_block = self.cipher.decrypt_block(block)
        if self._is_last_block(index):
            plaintext_block = PKCS7Unpadder(plaintext_block).value()
        self.result += plaintext_block    
    

class CBC(BlockCipherMode):
    
    def __init__(self, iv, block_size=None):
        BlockCipherMode.__init__(self, block_size)
        self.iv = iv

    def _xor(self, string1, string2):
        hex_string1 = BytesToHex(string1).value()
        hex_string2 = BytesToHex(string2).value()
        hex_result = HexXOR(hex_string1, hex_string2).value()
        return HexToBytes(hex_result).value()

    def _block_encryption_callback(self, index, block):
        if index == 0:
            self.last_ciphertext_block = self.iv 
        block = PKCS7Padder(block).value(self.block_size)
        xor_block = self._xor(block, self.last_ciphertext_block)
        ciphertext_block = self.cipher.encrypt_block(xor_block)        
        self.last_ciphertext_block = ciphertext_block
        self.result += ciphertext_block
    
    def _block_decryption_callback(self, index, block):
        if index == 0:
            self.last_ciphertext_block = self.iv
        decrypted_block = self.cipher.decrypt_block(block)
        plaintext_block = self._xor(decrypted_block,
                                    self.last_ciphertext_block)
        if self._is_last_block(index):
            plaintext_block = PKCS7Unpadder(plaintext_block).value()
        self.last_ciphertext_block = block
        self.result += plaintext_block