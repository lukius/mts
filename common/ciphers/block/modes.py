from string import BlockString

from common.padders import PKCS7Padder, PKCS7Unpadder
from common.xor import ByteXOR


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
    
    def _pad(self, string):
        last_block_index = string.block_count()-1
        last_block = string.get_block(last_block_index)
        last_block = PKCS7Padder(last_block).value(self.block_size)
        string.replace_block(last_block_index, last_block)
    
    def _unpad_if_needed(self, index, block):
        if self._is_last_block(index):
            block = PKCS7Unpadder(block).value()
        return block    
    
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
        if type(plaintext) != BlockString:
            plaintext = BlockString(plaintext, self.block_size)
        self._pad(plaintext)
        return self._iterate_blocks_with(plaintext, cipher,
                                         self._block_encryption_callback)
    
    def decrypt_with_cipher(self, ciphertext, cipher):
        if type(ciphertext) != BlockString:
            ciphertext = BlockString(ciphertext, self.block_size)
        return self._iterate_blocks_with(ciphertext, cipher,
                                         self._block_decryption_callback)


class ECB(BlockCipherMode):
    
    def _block_encryption_callback(self, index, block):
        self.result += self.cipher.encrypt_block(block)
    
    def _block_decryption_callback(self, index, block):
        plaintext_block = self.cipher.decrypt_block(block)
        plaintext_block = self._unpad_if_needed(index, plaintext_block)
        self.result += plaintext_block    
    

class CBC(BlockCipherMode):
    
    def __init__(self, iv, block_size=None):
        BlockCipherMode.__init__(self, block_size)
        self.iv = iv

    def _xor(self, string1, string2):
        return ByteXOR(string1, string2).value()

    def _block_encryption_callback(self, index, block):
        if index == 0:
            self.last_ciphertext_block = self.iv 
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
        plaintext_block = self._unpad_if_needed(index, plaintext_block)
        self.last_ciphertext_block = block
        self.result += plaintext_block