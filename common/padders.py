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
    
    def _pad(self, size, char):
        final_size = len(self.string) + size
        return RightPadder(self.string).value(final_size, char=chr(size))


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