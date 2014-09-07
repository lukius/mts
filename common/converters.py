import binascii
import math

from tools import Concatenation 

from common.endianness import BigEndian
from common.padders import LeftPadder


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
        bin_string = str()
        for i in range(0, len(self.hex_string), 2):
            byte = self.hex_string[i:i+2]
            bits = bin(int(byte, 16))[2:]
            bin_string += _ensure_length_multiple_of(bits, 8)
        return bin_string
    

class HexToBytes(object):
    
    def __init__(self, hex_string):
        self.hex_string = hex_string
        
    def value(self):
        return binascii.unhexlify(self.hex_string)
    

class HexToInt(object):
    
    def __init__(self, hex_string):
        self.hex_string = hex_string
        
    def value(self):
        return int(self.hex_string, 16)
            
    
class BinaryToHex(object):
    
    def __init__(self, bin_string):
        self.bin_string = bin_string
        
    def value(self):
        hex_string = hex(int(self.bin_string, 2))[2:]
        if hex_string[-1] == 'L':
            hex_string = hex_string[:-1]
        return _ensure_length_multiple_of(hex_string, 2)
    
    
class BinaryToBytes(object):
    
    def __init__(self, bin_string):
        self.bin_string = bin_string
        
    def value(self):
        integer = int(self.bin_string, 2)
        hex_string = _ensure_length_multiple_of('%x' % integer, 2)
        return binascii.unhexlify(hex_string)


class IntToHex(object):
    
    def __init__(self, integer):
        self.integer = integer
        
    def value(self):
        hex_string = hex(self.integer)[2:]
        if hex_string[-1] == 'L':
            hex_string = hex_string[:-1]
        return _ensure_length_multiple_of(hex_string, 2)


class IntToBinary(object):
    
    def __init__(self, integer):
        self.integer = integer
        
    def value(self):
        return bin(self.integer)[2:]
    
    
class IntToBytes(object):

    def __init__(self, integer):
        self.integer = integer
        
    def value(self, size=None):
        hex_string = IntToHex(self.integer).value()
        int_bytes = HexToBytes(hex_string).value()
        if size is not None and len(int_bytes) < size:
            int_bytes = LeftPadder(int_bytes).value(size, char='\0')
        return int_bytes 
    

class BytesConverter(object):
    
    def __init__(self, string, endianness=BigEndian):
        self.string = string
        self.endianness = endianness
        
    def value(self):
        string_bytes = self.endianness(self.string).value()
        return self._value(string_bytes)


class BytesToHex(BytesConverter):
        
    def _value(self, string):
        return binascii.hexlify(string)

    
class BytesToInt(BytesConverter):
        
    def _value(self, string):
        hex_string = BytesToHex(string).value()
        return HexToInt(hex_string).value()


class BytesToBinary(BytesConverter):
    
    def _to_bin(self, char):
        bin_string = bin(ord(char))[2:]
        return LeftPadder(bin_string).value(8)
        
    def _value(self, string):
        bin_strings = map(self._to_bin, string)
        return Concatenation(bin_strings).value()