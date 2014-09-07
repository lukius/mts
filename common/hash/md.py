import struct

from common.hash import HashFunction


class MDHashFunction(HashFunction):
    
    def __init__(self):
        HashFunction.__init__(self)
        self.mask = 0xffffffff
    
    def _rotate_left(self, integer, count):
        return ((integer << count) | (integer >> (32 - count))) & self.mask
    
    def _get_big_endian_words_from(self, chunk):
        return self._get_words_with_endianness(chunk, '>I')
    
    def _get_little_endian_words_from(self, chunk):
        return self._get_words_with_endianness(chunk, '<I')    
    
    def _get_words_with_endianness(self, chunk, endianness):
        words = list()
        for i in range(0, len(chunk), 4):
            word = struct.unpack(endianness, chunk[i:i+4])[0]
            words.append(word)
        return words
    
    def _not(self, a):
        return ~a & self.mask
    
    def _capped_sum(self, a, b):
        return (a + b) & self.mask
    
    def _update_registers_from(self, values):
        for i in range(len(self.registers)):
            self.registers[i] = self._capped_sum(self.registers[i],
                                                 values[i])
            
    def _pad_message(self, message):
        return self.padder()(message).value()   
    
    def hash(self, message):
        self._initialize_registers()
        message = self._pad_message(message)        
        
        for i in range(0, len(message), 64):
            values = self._process_chunk(message[i:i+64])
            self._update_registers_from(values)
            
        return self._compute_value()
    
    def _initialize_registers(self):
        raise NotImplementedError
    
    @classmethod
    def padder(cls):
        raise NotImplementedError
    
    def _process_chunk(self, chunk):
        raise NotImplementedError
    
    def _compute_value(self):
        raise NotImplementedError    