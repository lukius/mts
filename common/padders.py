import struct

from tools import AllEqual


class Padder(object):
    
    def __init__(self, string):
        self.string = string

    def _pad(self, size, char):
        raise NotImplementedError
    
    def value(self, size, char='0'):
        string = self.string
        length = len(self.string)
        if length < size:
            string = self._pad(size - length, char)
        return string
    

class MDPadder(Padder):
    
    def _pack_string(self):
        raise NotImplementedError    
    
    def value(self, size=None):
        if size is None:
            size = len(self.string)
        total_bit_length = size*8
        zero_bytes = (448 - total_bit_length - 8) % 512
        zero_bits = zero_bytes/8
        packed_length = struct.pack(self._pack_string(), total_bit_length)
        return '%s%s%s%s' % (self.string, '\x80', '\0'*zero_bits,
                             packed_length)


class SHA1Padder(MDPadder):
    
    def _pack_string(self):
        return '>Q'


class MD4Padder(MDPadder):
    
    def _pack_string(self):
        return '<Q'           


class PKCS7Padder(Padder):
    
    def value(self, size):
        length = len(self.string)
        if length % size == 0:
            string = self.string + chr(size)*size
        elif length < size:
            pad_size = size - length
            string = RightPadder(self.string).value(size, char=chr(pad_size))
        return string


class InvalidPaddingException(Exception):
    pass


class PKCS7Unpadder(object):
    
    def __init__(self, string):
        self.string = string

    def value(self):
        pad_char = self.string[-1]
        pad_size = ord(pad_char)
        all_equal = AllEqual(self.string[-pad_size:]).value(pad_char)
        if not all_equal:
            raise InvalidPaddingException
        return self.string[:-pad_size]


class FixedCharPadder(Padder):
    
    def _pad_with(self, padding):
        raise NotImplementedError

    def _pad(self, size, char):
        padding = char*size
        return self._pad_with(padding)
        
    
class LeftPadder(FixedCharPadder):
    
    def _pad_with(self, padding):
        return padding + self.string
    
    
class RightPadder(FixedCharPadder):
    
    def _pad_with(self, padding):
        return self.string + padding    