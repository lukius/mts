import random

from common.ciphers.block.aes import AES
from common.hash import HashFunction
from common.hash.md import MDHashFunction
from common.tools.endianness import BigEndian
from common.tools.misc import Concatenation
from common.tools.padders import RightPadder


class BasicHashFunctionFactory(object):
    
    @classmethod
    def build(cls, bit_size):
        max_int = (1<<bit_size) - 1
        initial_state = random.randint(0, max_int)
        byte_size = bit_size/8
        
        class BasicHashFunction(MDHashFunction):

            @classmethod
            def register_size(cls):
                return bit_size
            
            @classmethod
            def endianness(cls):
                return BigEndian
            
            @classmethod
            def initial_state(cls):
                return [initial_state]
        
            def _build_key_from_register(self):
                key = self.endianness().from_int(self.registers[0],
                                                 size=byte_size).value()
                return RightPadder(key).value(size=16, char='\x01')
            
            def _process_chunk(self, chunk):
                key = self._build_key_from_register()
                result = AES(key).encrypt(chunk).bytes()
                return [self.endianness().to_int(result[:byte_size]).value()]
            
        return BasicHashFunction


class ComposedHashFunction(HashFunction):
    
    def __init__(self, *functions):
        self.functions = functions
        
    def hash(self, message):
        hashes = map(lambda function: function().hash(message), self.functions)
        return Concatenation(hashes).value()