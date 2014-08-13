class Padder(object):
    
    def __init__(self, string):
        self.string = string
    
    def _pad(self, string, padding):
        raise NotImplementedError
        
    def value(self, size, char='0'):
        length = len(self.string)
        string = self.string
        if length < size:
            pad_size = size - length
            padding = char*pad_size
            string = self._pad(string, padding)
        return string
    
    
class LeftPadder(Padder):
    
    def _pad(self, string, padding):
        return padding + string
    
    
class RightPadder(Padder):
    
    def _pad(self, string, padding):
        return string + padding
