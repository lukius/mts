class ECBEncryptionFinder(object):
    
    BLOCK_SIZE = 16
    
    def __init__(self, hex_strings):
        self.hex_strings = hex_strings
        
    def _less_than(self, number1, number2):
        return number2 is None or number1 < number2
        
    def _build_block_set(self, hex_string):
        return set(hex_string[i:i+2*self.BLOCK_SIZE]
                   for i in range(0, len(hex_string), 2*self.BLOCK_SIZE))
        
    def value(self):
        min_blocks = None
        for hex_string in self.hex_strings:
            block_set = self._build_block_set(hex_string)
            size = len(block_set)
            if self._less_than(size, min_blocks):
                candidate_string = hex_string
                min_blocks = len(block_set)
        return candidate_string
    
    
if __name__ == '__main__':
    target_file = 'data/8.txt'
    hex_strings = open(target_file, 'r').read().splitlines()
    print ECBEncryptionFinder(hex_strings).value()