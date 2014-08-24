from modes import CTR

from common.converters import LittleEndian


class CTRModeCounter(object):
    
    def __init__(self, block_size):
        self.block_size = block_size if block_size is not None\
                          else CTR.DEFAULT_BLOCK_SIZE
    
    def count(self, index):
        raise NotImplementedError


class DefaultCounter(CTRModeCounter):
    
    def count(self, index):
        return LittleEndian(index).value(self.block_size)
    
    
class NonceBasedCounter(CTRModeCounter):
    
    def __init__(self, nonce, block_size):
        CTRModeCounter.__init__(self, block_size)
        self.nonce = nonce
    
    def count(self, index):
        nonce = LittleEndian(self.nonce).value(self.block_size/2)
        index = LittleEndian(index).value(self.block_size/2)
        return nonce + index