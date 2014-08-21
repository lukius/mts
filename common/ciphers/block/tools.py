from modes import ECB, CBC


class ECB_CBCDetectionOracle(object):
    
    BLOCKS = 20

    def __init__(self, encrypter, block_size=None):
        self.encrypter = encrypter
        self.block_size = block_size if block_size is not None \
                          else ECB.DEFAULT_BLOCK_SIZE

    def _all_equal(self, blocks):
        return len(set(blocks)) == 1
    
    def _build_chosen_plaintext(self):
        return 'X'*self.block_size*self.BLOCKS
    
    def value(self):
        plaintext = self._build_chosen_plaintext()
        ciphertext = self.encrypter.encrypt(plaintext)
        blocks = [ciphertext.get_block(i) for i in range(5)]
        # Skip first block in case it includes random, non-controlled data.
        if self._all_equal(blocks[1:]):
            mode = ECB.name()
        else:
            mode = CBC.name()
        return mode
    
    
class BlockRetriever(object):
    
    def __init__(self, message, block_size=None):
        self.message = message
        self.block_size = block_size if block_size is not None \
                          else ECB.DEFAULT_BLOCK_SIZE
        
    def value(self, index):
        start_index = index*self.block_size
        end_index = start_index+self.block_size
        return self.message[start_index:end_index]