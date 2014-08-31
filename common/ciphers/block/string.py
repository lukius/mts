from math import ceil


class BlockString(object):
    """An abstraction of input/output of block ciphers.
    """
    
    def __init__(self, string=None, block_size=None):
        from modes import BlockCipherMode
        self.string = string if string is not None else str()
        self._block_size = block_size if block_size is not None\
                           else BlockCipherMode.DEFAULT_BLOCK_SIZE
                          
    def _get_boundaries_for(self, index):
        start_index = index*self._block_size
        end_index = start_index + self._block_size
        return (start_index, end_index)
    
    def is_last_block_index(self, i):
        return i == self.block_count()-1
    
    def block_size(self):
        return self._block_size
        
    def block_count(self):
        return int(ceil(len(self.string)/float(self._block_size)))
    
    def get_block(self, index):
        from tools import BlockRetriever
        block_count = self.block_count()
        if index >= block_count or index < -block_count:
            raise IndexError('block index out of range')
        if index < 0:
            index += block_count
        return BlockRetriever(self.string, self._block_size).value(index)
    
    def remove_block(self, index):
        start_index, end_index = self._get_boundaries_for(index)
        self.string = self.string[:start_index] + self.string[end_index:]
        
    def replace_block(self, index, new_block):
        start_index, end_index = self._get_boundaries_for(index)
        self.string = self.string[:start_index] + new_block + \
                      self.string[end_index:]
    
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
        return BlockString(result, self._block_size)
    
    def __iter__(self):
        self.current_block_index = 0
        return self
    
    def next(self):
        if self.current_block_index >= self.block_count():
            raise StopIteration
        block = self.get_block(self.current_block_index)
        self.current_block_index += 1
        return block