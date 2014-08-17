from common.padders import RightPadder


class BlockCipherMode(object):
    
    def encrypt_with_cipher(self, message, cipher):
        raise NotImplementedError
    
    def decrypt_with_cipher(self, message, cipher):
        raise NotImplementedError    


class ECB(BlockCipherMode):
    
    BLOCK_SIZE = 16
    
    def _add_padding(self, block):
        padding_char = chr(self.BLOCK_SIZE - len(block))
        return RightPadder(block).value(self.BLOCK_SIZE, char=padding_char)
    
    def _remove_padding(self, block):
        last_char = ord(block[-1])
        if 1 <= last_char <= self.BLOCK_SIZE - 1:
            block = block[:-last_char]
        return block

    def _ensure_proper_block_size(self, block):
        if len(block) < self.BLOCK_SIZE:
            block = self._add_padding(block)
        return block
    
    def _is_last_block(self, index, length):
        return index + self.BLOCK_SIZE >= length
    
    def encrypt_with_cipher(self, message, cipher):
        ciphertext = str()
        for i in range(0, len(message), self.BLOCK_SIZE):
            block = message[i:i+self.BLOCK_SIZE]
            block = self._ensure_proper_block_size(block)
            ciphertext += cipher.encrypt_block(block)
        return ciphertext
    
    def decrypt_with_cipher(self, message, cipher):
        plaintext = str()
        message_length = len(message)
        for i in range(0, message_length, self.BLOCK_SIZE):
            block = message[i:i+self.BLOCK_SIZE]
            plaintext_block = cipher.decrypt_block(block)
            if self._is_last_block(i, message_length):
                plaintext_block = self._remove_padding(plaintext_block)
            plaintext += plaintext_block
        return plaintext