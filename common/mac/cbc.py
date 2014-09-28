from common.mac import MessageAuthenticationCode
from common.ciphers.block.aes import AES
from common.ciphers.block.modes import CBC


class CBC_MAC(MessageAuthenticationCode):
    
    def __init__(self, key, cipher=AES, iv=None, block_size=None):
        MessageAuthenticationCode.__init__(self, key)
        self.cipher = cipher(self.key)
        self.block_size = block_size if block_size is not None\
                          else CBC.DEFAULT_BLOCK_SIZE
        self.iv = iv if iv is not None else '\0'*self.block_size
        
    def get_block_size(self):
        return self.block_size
                          
    def value(self, message):
        # The encryption yields a BlockString. The get_block method will then
        # project its last block.
        return self.cipher.encrypt(message, mode=CBC(self.iv)).get_block(-1)