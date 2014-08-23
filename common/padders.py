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


class PKCS7Padder(Padder):
    
    def value(self, size):
        length = len(self.string)
        if length % size == 0:
            string = self.string + chr(size)*size
        elif length < size:
            pad_size = size - length
            string = RightPadder(self.string).value(size, char=chr(pad_size))
        return string


class PKCS7Unpadder(object):
    
    def __init__(self, string):
        self.string = string

    def value(self):
        pad_char = self.string[-1]
        pad_size = ord(pad_char)
        all_equal = AllEqual(self.string[-pad_size:]).value(pad_char)
        if not all_equal:
            raise RuntimeError('bad padding')
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