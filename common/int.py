class FixedSizeInteger(object):

    def __init__(self, value=0, bits=32):
        self.bits = bits
        self.value = self._truncate(abs(value))
        
    def _truncate(self, value):
        mask = (2**self.bits) - 1
        return value & mask
    
    def _bits_of(self, integer):
        bits = 0
        if type(integer) == type(self):
            bits = integer.bits
        return bits

    def _operate_with(self, integer, operation): 
        value = operation(self.value, int(integer))
        int_bits = self._bits_of(integer)
        bits = max(self.bits, int_bits)
        return self.__class__(value=value, bits=bits)
    
    def __radd__(self, integer):
        return self + integer

    def __add__(self, integer):
        def add(a, b):
            return a + b
        return self._operate_with(integer, add)

    def __rsub__(self, integer):
        return -1 * (self - integer)

    def __sub__(self, integer):
        def sub(a, b):
            return a - b
        return self._operate_with(integer, sub)
 
    def __rmul__(self, integer):
        return self * integer    

    def __mul__(self, integer):
        def mul(a, b):
            return a * b
        return self._operate_with(integer, mul)
    
    def __rdiv__(self, integer):
        return int(integer) / self.value

    def __div__(self, integer):
        def div(a, b):
            return a / b
        return self._operate_with(integer, div)
 
    def __lshift__(self, integer):
        value = self.value << int(integer)
        return self.__class__(value=value, bits=self.bits)
 
    def __rshift__(self, integer):
        value = self.value >> int(integer)
        return self.__class__(value=value, bits=self.bits)

    def __rand__(self, integer):
        return self & integer
 
    def __and__(self, integer):
        def _and(a, b):
            return a & b
        return self._operate_with(integer, _and)
 
    def __ror__(self, integer):
        return self | integer
 
    def __or__(self, integer):
        def _or(a, b):
            return a | b
        return self._operate_with(integer, _or)
 
    def __rxor__(self, integer):
        return self ^ integer 
 
    def __xor__(self, integer):
        def xor(a, b):
            return a ^ b
        return self._operate_with(integer, xor)
 
    def __invert__(self):
        value = self._truncate(~self.value)
        return self.__class__(value=value, bits=self.bits)
 
    def __int__(self):
        return int(self.value)
    
    def __abs__(self):
        return abs(self.value)

    def __repr__(self):
        return repr(self.value)
    
    def __str__(self):
        return str(self.value)
    
    def __index__(self):
        return self.value.__index__()

    def __cmp__(self, integer):
        integer = int(integer)
        value = 0
        if self.value > integer:
            value = 1
        elif self.value < integer:
            value = -1
        return value