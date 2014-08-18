from common.converters import ASCIIToHex, HexToASCII
from common.padders import PKCS7Padder
from common.xor import HexXOR


class BlockCipherMode(object):
    
    BLOCK_SIZE = 16

    def _is_last_block(self, index):
        return index + self.BLOCK_SIZE >= len(self.message)
    
    def _remove_padding(self, block):
        last_char = ord(block[-1])
        if 1 <= last_char <= self.BLOCK_SIZE - 1:
            block = block[:-last_char]
        return block
    
    def _iterate_blocks(self, callback):
        for i in range(0, len(self.message), self.BLOCK_SIZE):
            block = self.message[i:i+self.BLOCK_SIZE]
            callback(i, block)
    
    def encrypt_with_cipher(self, message, cipher):
        raise NotImplementedError

    def _decryption_block_callback(self, message, cipher):
        raise NotImplementedError
    
    def decrypt_with_cipher(self, plaintext, cipher):
        self.result = str()
        self.cipher = cipher
        self.message = plaintext
        self._iterate_blocks(self._decryption_block_callback)
        return self.result    


class ECB(BlockCipherMode):
    
    def encrypt_with_cipher(self, message, cipher):
        ciphertext = str()
        for i in range(0, len(message), self.BLOCK_SIZE):
            block = message[i:i+self.BLOCK_SIZE]
            block = PKCS7Padder(block).value(self.BLOCK_SIZE)
            ciphertext += cipher.encrypt_block(block)
        return ciphertext
    
    def _decryption_block_callback(self, index, block):
        plaintext_block = self.cipher.decrypt_block(block)
        if self._is_last_block(index):
            plaintext_block = self._remove_padding(plaintext_block)
        self.result += plaintext_block    
    

class CBC(BlockCipherMode):
    
    def __init__(self, iv):
        BlockCipherMode.__init__(self)
        self.iv = iv

    def _xor(self, string1, string2):
        hex_string1 = ASCIIToHex(string1).value()
        hex_string2 = ASCIIToHex(string2).value()
        hex_result = HexXOR(hex_string1, hex_string2).value()
        return HexToASCII(hex_result).value()

    def encrypt_with_cipher(self, plaintext, cipher):
        raise NotImplementedError
    
    def _decryption_block_callback(self, index, block):
        if index == 0:
            self.last_ciphertext_block = self.iv
        decrypted_block = self.cipher.decrypt_block(block)
        plaintext_block = self._xor(decrypted_block,
                                    self.last_ciphertext_block)
        if self._is_last_block(index):
            plaintext_block = self._remove_padding(plaintext_block)
        self.last_ciphertext_block = block
        self.result += plaintext_block