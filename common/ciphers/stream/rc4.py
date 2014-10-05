from common.ciphers.stream import StreamCipher


class RC4(StreamCipher):
    
    def __init__(self, key):
        StreamCipher.__init__(self)
        self._init_state_from(key)
        
    def _capped_sum(self, a, b):
        return (a + b) % 256
    
    def _swap_S(self, i, j):
        self.S[i], self.S[j] = self.S[j], self.S[i]
        
    def _init_state_from(self, key):
        # Implementation of the KSA algorithm.
        key_length = len(key)
        self.i = self.j = 0
        self.S = [i for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + self.S[i] + ord(key[i % key_length])) % 256
            self._swap_S(i, j)
    
    def _compute_key_bytes(self, byte_count):
        # Implementation of the PRGA algorithm.
        key_bytes = str()
        for _ in range(byte_count):
            self.i = self._capped_sum(self.i, 1)
            self.j = self._capped_sum(self.j, self.S[self.i])
            self._swap_S(self.i, self.j)
            index = self._capped_sum(self.S[self.i], self.S[self.j])
            key_byte = self.S[index]
            key_bytes += chr(key_byte)
        return key_bytes