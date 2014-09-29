from common.hash import HashFunction
from common.tools.padders import MDPadder
from common.tools.misc import Concatenation


class MDHashFunction(HashFunction):
    
    @classmethod
    def bits(cls):
        return 32
    
    def __init__(self):
        HashFunction.__init__(self)
        self.mask = (1 << self.bits()) - 1
        
    def _to_bytes(self, integer):
        byte_size = self.bits()/8
        return self.endianness().from_int(integer, size=byte_size).value()        
    
    def _rotate_left(self, integer, count):
        bits = self.bits()
        return ((integer << count) | (integer >> (bits - count))) & self.mask
    
    def _get_words_from(self, chunk):
        words = list()
        for i in range(0, len(chunk), 4):
            word = self.endianness().to_int(chunk[i:i+4]).value()
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
    
    @classmethod
    def endianness(cls):
        raise NotImplementedError    

    def _initialize_registers(self):
        raise NotImplementedError
    
    def _process_chunk(self, chunk):
        raise NotImplementedError