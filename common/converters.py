import binascii
import math

from common.padders import LeftPadder
from tools import concatenate


def _ensure_length_multiple_of(string, value):
    length = len(string)
    if length % value != 0:
        pad_size = int(value*math.ceil(length/float(value)))
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
        hex_string = hex(int(self.bin_string, 2))[2:]
        if hex_string[-1] == 'L':
            hex_string = hex_string[:-1]
        return _ensure_length_multiple_of(hex_string, 2)


class IntToHex(object):
    
    def __init__(self, integer):
        self.integer = integer
        
    def value(self):
        return hex(self.integer)[2:]
    
    
class HexToASCII(object):
    
    def __init__(self, hex_string):
        self.hex_string = hex_string
        
    def value(self):
        return binascii.unhexlify(self.hex_string)


class ASCIIToHex(object):
    
    def __init__(self, string):
        self.string = string
        
    def value(self):
        return binascii.hexlify(self.string)


class ASCIIToBinary(object):
    
    def __init__(self, string):
        self.string = string
    
    def _to_bin(self, char):
        bin_string = bin(ord(char))[2:]
        return LeftPadder(bin_string).value(8)
        
    def value(self):
        bin_strings = map(self._to_bin, self.string)
        return concatenate(bin_strings)        