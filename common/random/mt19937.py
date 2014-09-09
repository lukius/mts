from math import ceil

from common.tools.converters import IntToBytes
from common.tools.misc import Concatenation


class MersenneTwister(object):
    
    STATE_SIZE = 624
    
    def __init__(self, seed):
        self.seed = seed
        self._init_state()
        
    def _init_state(self):
        self.index = 0
        self.state = [self.seed]  
        for i in range(1, self.STATE_SIZE):
            previous = self.state[i-1]
            xor = previous ^ (previous >> 30)
            current = (i + 1812433253 * xor) & 0xffffffff
            self.state.append(current)
    
    def _update_state(self):
        for i in range(self.STATE_SIZE):
            value = (self.state[i] & 0x80000000) +\
                    (self.state[(i+1) % self.STATE_SIZE] & 0x7fffffff)
            self.state[i] = self.state[(i+397) % self.STATE_SIZE] ^\
                            (value >> 1)
            if value % 2 != 0:
                self.state[i] ^= 2567483615
    
    def _increment_index(self):
        self.index = (self.index + 1) % self.STATE_SIZE
        
    def rand_bytes(self, count):
        int_count = int(ceil(count/4.0))
        integers = [self.rand() for _ in range(int_count)]
        int_bytes = map(lambda integer: IntToBytes(integer).value(), integers)
        return Concatenation(int_bytes).value()[:count]  
        
    def rand(self):
        if self.index == 0:
            self._update_state()
        
        value = self.state[self.index]
        value ^= value >> 11
        value ^= (value << 7) & 2636928640
        value ^= (value << 15) & 4022730752
        value ^= value >> 18
        
        self._increment_index()
        
        return value