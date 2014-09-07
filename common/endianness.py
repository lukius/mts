class Endianness(object):
    
    @classmethod
    def from_int(cls, integer, size=None):
        from converters import IntToBytes
        string = IntToBytes(integer).value(size)
        return cls(string)
    
    def __init__(self, byte_string):
        self.string = self._value(byte_string)
        
    def value(self):
        return self.string
    
    def _value(self, string):
        raise NotImplementedError


class LittleEndian(Endianness):
    
    def _value(self, string):
        return string[::-1]
    
    
class BigEndian(Endianness):
    
    def _value(self, string):
        return string