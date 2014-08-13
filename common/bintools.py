from math import ceil

from padder import LeftPadder
from tools import concatenate


def _ensure_length_multiple_of(string, value):
    length = len(string)
    if length % value != 0:
        pad_size = int(value*ceil(length/float(value)))
        string = LeftPadder(string).value(pad_size)
    return string


class HexToBinary(object):
    
    def __init__(self, byte_string):
        self.hex_string = byte_string
    
    def value(self):
        bin_string = bin(int(self.hex_string, 16))[2:]
        return _ensure_length_multiple_of(bin_string, 8)
    
    
class BinaryToHex(object):
    
    def __init__(self, bin_string):
        self.bin_string = bin_string
        
    def value(self):
        hex_string = str()
        bin_string = _ensure_length_multiple_of(self.bin_string, 4)
        for i in xrange(0, len(bin_string), 4):
            byte = bin_string[i:i+4]
            hex_value = hex(int(byte, 2))[2:]
            hex_string += hex_value
        return hex_string


class ASCIIToBinary(object):
    
    def __init__(self, string):
        self.string = string
    
    def _to_bin(self, char):
        bin_string = bin(ord(char))[2:]
        return LeftPadder(bin_string).value(8)
        
    def value(self):
        bin_strings = map(self._to_bin, self.string)
        return concatenate(bin_strings)        