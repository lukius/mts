from common.ciphers.stream import StreamCipher
from common.random.mt19937 import MersenneTwister


class MersenneTwisterCipher(StreamCipher):
    
    def __init__(self, key):
        StreamCipher.__init__(self)
        self.prng = MersenneTwister(seed=key)
        
    def _compute_key_bytes(self, byte_count):
        return self.prng.rand_bytes(byte_count)    
