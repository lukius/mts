from modes import CTR

from common.endianness import LittleEndian


class CTRModeCounter(object):
    
    def __init__(self, block_size):
        self.block_size = block_size if block_size is not None\
                          else CTR.DEFAULT_BLOCK_SIZE
    
    def count(self, index):
        raise NotImplementedError


class DefaultCounter(CTRModeCounter):
    
    def count(self, index):
        return LittleEndian.from_int(index, size=self.block_size).value()
    
    
class NonceBasedCounter(CTRModeCounter):
    
    def __init__(self, nonce, block_size):
        CTRModeCounter.__init__(self, block_size)
        self.nonce = nonce
    
    def count(self, index):
        size = self.block_size/2
        nonce = LittleEndian.from_int(self.nonce, size=size).value()
        index = LittleEndian.from_int(index, size=size).value()
        return nonce + index