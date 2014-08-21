from math import ceil


class BlockString(object):
    """An abstraction of input/output of block ciphers.
    """
    
    def __init__(self, string=None, block_size=None):
        from modes import BlockCipherMode
        self.string = string if string is not None else str()
        self.block_size = block_size if block_size is not None\
                          else BlockCipherMode.DEFAULT_BLOCK_SIZE
        
    def block_count(self):
        return int(ceil(len(self.string)/float(self.block_size)))
    
    def get_block(self, index):
        from tools import BlockRetriever
        if index >= self.block_count():
            raise IndexError('block index out of range')
        return BlockRetriever(self.string, self.block_size).value(index)
    
    def bytes(self):
        return self.string

    def __str__(self):
        return self.string

    def __repr__(self):
        return self.string
    
    def __len__(self):
        return len(self.string)
    
    def __add__(self, string):
        result = self.string + str(string)
        return BlockString(result, self.block_size)
    
    def __iter__(self):
        self.current_block_index = 0
        return self
    
    def next(self):
        if self.current_block_index >= self.block_count():
            raise StopIteration
        block = self.get_block(self.current_block_index)
        self.current_block_index += 1
        return block