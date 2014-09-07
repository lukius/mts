from common.endianness import BigEndian, LittleEndian
from common.hash import HashFunction
from common.padders import MDPadder
from common.tools import Concatenation


class MDHashFunction(HashFunction):
    
    @classmethod
    def endianness(cls):
        return BigEndian

    def __init__(self):
        HashFunction.__init__(self)
        self.mask = 0xffffffff
        
    def _to_bytes(self, integer):
        return self.endianness().from_int(integer, size=4).value()        
    
    def _rotate_left(self, integer, count):
        return ((integer << count) | (integer >> (32 - count))) & self.mask
    
    def _get_big_endian_words_from(self, chunk):
        return self._get_words_with_endianness(chunk, BigEndian)
    
    def _get_little_endian_words_from(self, chunk):
        return self._get_words_with_endianness(chunk, LittleEndian)    
    
    def _get_words_with_endianness(self, chunk, endianness):
        words = list()
        for i in range(0, len(chunk), 4):
            word = endianness.to_int(chunk[i:i+4]).value()
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
        return MDPadder(message, self.endianness()).value()   
    
    def hash(self, message):
        self._initialize_registers()
        message = self._pad_message(message)        
        
        for i in range(0, len(message), 64):
            values = self._process_chunk(message[i:i+64])
            self._update_registers_from(values)
            
        return self._compute_value()
    
    def _compute_value(self):
        registers = map(self._to_bytes, self.registers)
        return Concatenation(registers).value()    

    def _initialize_registers(self):
        raise NotImplementedError
    
    def _process_chunk(self, chunk):
        raise NotImplementedError