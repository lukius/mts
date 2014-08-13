from math import ceil

from padder import LeftPadder


class BytesToBinary(object):
    
    def __init__(self, byte_string):
        self.byte_string = byte_string
    
    def value(self):
        bin_string = bin(int(self.byte_string, 16))[2:]
        length = len(bin_string)
        if length % 8 != 0:
            pad_size = int(8*ceil(length/8.0))
            bin_string = LeftPadder(bin_string).value(pad_size)
        return bin_string


class ASCIIToBinary(object):
    
    def __init__(self, string):
        self.string = string
    
    def _to_bin(self, char):
        bin_string = bin(ord(char))[2:]
        return LeftPadder(bin_string).value(8)
        
    def value(self):
        def concatenate(strings):
            return ''.join(strings)
        
        bin_strings = map(self._to_bin, self.string)
        return concatenate(bin_strings)        