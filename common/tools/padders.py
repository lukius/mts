from common.tools.misc import AllEqual, RandomByteGenerator


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
    
    def __init__(self, string, endianness):
        Padder.__init__(self, string)
        self.endianness = endianness
    
    def value(self, size=None):
        if size is None:
            size = len(self.string)
        total_bit_length = size*8
        zero_bytes = (448 - total_bit_length - 8) % 512
        zero_bits = zero_bytes/8
        length = self.endianness.from_int(total_bit_length, size=8).value()
        return '%s%s%s%s' % (self.string, '\x80', '\0'*zero_bits, length)


class PKCS7Padder(Padder):
    
    def value(self, size):
        length = len(self.string)
        quotient, remaining_bytes = divmod(length, size)
        pad_size = size - remaining_bytes
        string = RightPadder(self.string).value(size*(quotient+1),
                                                    char=chr(pad_size))
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


class PKCS1_5Padder(Padder):

    def _build_padding(self, size):
        byte_generator = RandomByteGenerator()
        padding = byte_generator.value(size)
        return padding.replace('\x00', byte_generator.value(1))
    
    def value(self, size):
        data_length = len(self.string)
        if data_length > size - 11:
            raise RuntimeError('data too long to PKCS1.5-pad it')
        padding_length = size - 3 - data_length
        padding = self._build_padding(padding_length)
        return '\x00\x02%s\x00%s' % (padding, self.string)


class PKCS1_5Unpadder(object):
    
    def __init__(self, size):
        self.size = size

    def value(self, string):
        string = LeftPadder(string).value(self.size, char='\0')
        zero_index = string[2:].find('\x00')
        if string[0] != '\x00' or string[1] != '\x02' or zero_index < 0:
            raise InvalidPaddingException
        return string[3+zero_index:]


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