from common.tools.converters import IntToHex, HexToInt, BytesToInt, IntToBytes
from common.tools.padders import LeftPadder


class XOR(object):
    
    def __init__(self, *strings):
        self.strings = strings
        
    def _to_int(self, string):
        converter = self._to_int_converter()
        integer = converter(string).value() if string else 0
        return integer
    
    def _from_int(self, integer):
        converter = self._from_int_converter() 
        string = converter(integer).value()
        length = max(map(len, self.strings))
        pad_char = self._pad_char()
        return LeftPadder(string).value(length, char=pad_char)
        
    def value(self):
        integers = map(self._to_int, self.strings)
        xored = reduce(lambda xor, integer: xor ^ integer, integers, 0)
        return self._from_int(xored)


class HexXOR(XOR):
    
    def _to_int_converter(self):
        return HexToInt
    
    def _from_int_converter(self):
        return IntToHex
    
    def _pad_char(self):
        return '0'


class ByteXOR(XOR):
    
    def _to_int_converter(self):
        return BytesToInt
    
    def _from_int_converter(self):
        return IntToBytes   

    def _pad_char(self):
        return '\0'