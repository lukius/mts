from common.challenge import MatasanoChallenge
from common.ciphers.block.tools import ECBDecrypter, ECBEncryptionOracle
from common.tools import RandomByteGenerator


class ECBEncryptionOracleWithRandomPrefix(ECBEncryptionOracle):
    
    def __init__(self):
        ECBEncryptionOracle.__init__(self)
        self.random_prefix = RandomByteGenerator().value()
    
    def encrypt(self, plaintext):
        plaintext = self.random_prefix + plaintext
        return ECBEncryptionOracle.encrypt(self, plaintext)


class ECBDecrypterForRandomPrefixOracle(ECBDecrypter):
    
    BLOCK_SIZE = 16
    EXPECTED_EQUAL_BLOCKS = 3
    
    def _blocks_equal(self, block, blocks):
        return all(map(lambda _block: _block == block, blocks))
    
    def _search_equal_blocks_starting_point(self, ciphertext):
        for index, block in enumerate(ciphertext):
            next_blocks = [ciphertext.get_block(i)
                           for i in range(index+1,
                                          index+self.EXPECTED_EQUAL_BLOCKS)]
            if self._blocks_equal(block, next_blocks):
                return index 
    
    def _discover_random_prefix_length(self):
        probe = 'X'*((1+self.EXPECTED_EQUAL_BLOCKS)*self.block_size - 1)
        ciphertext = self.oracle.encrypt(probe)
        start_index = self._search_equal_blocks_starting_point(ciphertext)
        target_block = ciphertext.get_block(start_index)
        for k in xrange(self.block_size, 2*self.block_size):
            output = self.oracle.encrypt('X'*k)
            if output.get_block(start_index) == target_block:
                # This magic can be understood as follows:
                #  * We have (start_index - 1) full random-byte blocks.
                #  * We have just found that k bytes fill the last random-byte
                #    block and make one block worth of Xs.
                #  * Thus, the last random-byte block must have
                #    block_size - (k - block_size) random bytes
                #  * Then, total random byte length equals
                #   (start_index - 1)*block_size + block_size - (k-block_size)
                #   = (start_index + 1)*block_size - k 
                return (start_index+1)*self.block_size - k
        
    def value(self):
        # TODO: fix block size calculation.
        self.block_size = self.BLOCK_SIZE
        prefix_length = self._discover_random_prefix_length()
        min_block_count, additional_bytes = divmod(prefix_length,
                                                   self.block_size)
        self.skip_blocks = min_block_count
        if additional_bytes != 0:
            self.skip_blocks += 1
            self.pad_string = 'X'*(self.block_size - additional_bytes)
        return ECBDecrypter._decrypt_string(self)
        

class Set2Challenge6(MatasanoChallenge):

    def expected_value(self):
        return 'Rollin\' in my 5.0\n' +\
               'With my rag-top down so my hair can blow\n' +\
               'The girlies on standby waving just to say hi\n' +\
               'Did you stop? No, I just drove by\n'

    def value(self):
        oracle = ECBEncryptionOracleWithRandomPrefix()
        return ECBDecrypterForRandomPrefixOracle(oracle).value()