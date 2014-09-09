class Endianness(object):
    
    @classmethod
    def from_int(cls, integer, size=None):
        from common.tools.converters import IntToBytes
        string = IntToBytes(integer).value(size)
        return cls(string)
    
    @classmethod
    def to_int(cls, string):
        from common.tools.converters import BytesToInt
        integer = BytesToInt(string, endianness=cls).value()
        return cls(integer)
    
    def __init__(self, value):
        if type(value) is str:
            self.result = self._value(value)
        else:
            self.result = value
        
    def value(self):
        return self.result
    
    def _value(self, string):
        raise NotImplementedError


class LittleEndian(Endianness):
    
    def _value(self, string):
        return string[::-1]
    
    
class BigEndian(Endianness):
    
    def _value(self, string):
        return string