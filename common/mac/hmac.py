from common.mac import MessageAuthenticationCode
from common.tools.padders import RightPadder
from common.tools.xor import ByteXOR


class HMAC(MessageAuthenticationCode):
    
    BLOCK_SIZE = 64
    
    def __init__(self, key, hash_function, block_size=None):
        MessageAuthenticationCode.__init__(self, key)
        self.hash_function = hash_function()
        self.block_size = block_size if block_size is not None\
                          else self.BLOCK_SIZE
                          
    def _build_key(self):
        key = self.key
        if len(self.key) > self.block_size:
            key = self.hash_function.hash(self.key)
        return RightPadder(key).value(self.block_size, char='\0')
    
    def value(self, message):
        key = self._build_key()
        outer_padding = ByteXOR(key, '\x5c' * self.block_size).value()
        inner_padding = ByteXOR(key, '\x36' * self.block_size).value()
        hashed_message = self.hash_function.hash(inner_padding + message)
        return self.hash_function.hash(outer_padding + hashed_message)