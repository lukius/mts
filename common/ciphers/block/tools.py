from modes import ECB, CBC
from common.ciphers.block.aes import AES

from common.tools.base64 import Base64Decoder
from common.tools.misc import RandomByteGenerator, AllEqual


class ECB_CBCDetectionOracle(object):
    
    BLOCKS = 20

    def __init__(self, encrypter, block_size=None):
        self.encrypter = encrypter
        self.block_size = block_size if block_size is not None \
                          else ECB.DEFAULT_BLOCK_SIZE

    def _build_chosen_plaintext(self):
        return 'X'*self.block_size*self.BLOCKS
    
    def value(self):
        plaintext = self._build_chosen_plaintext()
        ciphertext = self.encrypter.encrypt(plaintext)
        blocks = [ciphertext.get_block(i) for i in range(5)]
        # Skip first block in case it includes random, non-controlled data.
        all_blocks_equal = AllEqual(blocks[1:]).value()
        if all_blocks_equal:
            mode = ECB.name()
        else:
            mode = CBC.name()
        return mode


class ECBEncryptionOracle(object):
    
    BLOCK_SIZE = 16
    
    def __init__(self):
        key = RandomByteGenerator().value(self.BLOCK_SIZE)
        self.cipher = AES(key)
        self.trailing_string = self._decode_trailing_string()
    
    def _trailing_string(self):
        return 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXk' +\
               'gaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZy' +\
               'BqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvd' +\
               'mUgYnkK'
               
    def _decode_trailing_string(self):
        string = self._trailing_string()
        return Base64Decoder().decode(string)
    
    def encrypt(self, plaintext):
        plaintext += self.trailing_string
        return self.cipher.encrypt(plaintext, mode=ECB())


class ECBDecrypter(object):
    
    MAX_BLOCK_SIZE_TRIES = 65
    MAX_BLOCK_SIZE = 64
    
    def __init__(self, oracle):
        self.oracle = oracle
        self.pad_string = str()
        self.skip_blocks = 0
        
    def _encrypt(self, string):
        ciphertext = self.oracle.encrypt(self.pad_string + string)
        self._remove_blocks_to_skip(ciphertext)
        return ciphertext
    
    def _remove_blocks_to_skip(self, ciphertext):
        for _ in xrange(self.skip_blocks):
            ciphertext.remove_block(0)
        
    def _get_longest_common_prefix(self, string1, string2):
        for i in range(self.MAX_BLOCK_SIZE):
            size = self.MAX_BLOCK_SIZE - i
            if string1[:size] == string2[:size]:
                return size
        return 0
        
    def _discover_block_size(self):
        previous_output = self.oracle.encrypt('X').bytes()
        for count in range(2, self.MAX_BLOCK_SIZE_TRIES):
            input_string = 'X'*count
            output = self.oracle.encrypt(input_string).bytes()
            longest_prefix = self._get_longest_common_prefix(output,
                                                             previous_output)
            previous_output = output
            if longest_prefix and longest_prefix % 8 == 0:
                return longest_prefix
            
    def _ensure_ecb_mode(self):
        mode = ECB_CBCDetectionOracle(self.oracle, self.block_size).value()
        if mode != ECB.name():
            raise RuntimeError('encryption mode not supported')
        
    def _discover_string_length(self):
        # Discover how many blocks the string uses.
        # Its actual length, however, is still unknown (might be padded).
        block_count = self._encrypt('').block_count()

        # Now, push one more byte at a time until a new block is used.
        # Once this happens, the number of bytes pushed is the value we
        # are looking for.
        for i in range(1, self.block_size):
            input_string = 'X'*i
            output = self._encrypt(input_string)
            if output.block_count() > block_count:
                return block_count*self.block_size - i
        
    def _get_target_block(self, index):
        ciphertext = self._encrypt(self.input_string)
        # Index of the encrypted block where the desired byte is hiding.
        target_block_index = (index-1)/self.block_size
        return ciphertext.get_block(target_block_index)
    
    def _get_possible_blocks(self):
        possible_blocks = dict()
        for byte in range(255):
            char = chr(byte)
            input_string = self.test_string + char 
            ciphertext = self._encrypt(input_string)
            block = ciphertext.get_block(0)
            possible_blocks[block] = char
        return possible_blocks
    
    def _update_input_strings(self, byte):
        # Insert the byte into our test string and shift it.
        self.test_string = self.test_string[1:] + byte
        if not self.input_string:
            # If we've just completed one block, start over for the next one.
            self.input_string = self.test_string
        else:
            # Otherwise, make room for the next byte we want to decipher.
            self.input_string = self.input_string[:-1]
        
    def _discover_byte(self, index, string):
        # Get the actual encrypted block that is holding our byte.
        target_block = self._get_target_block(index)
        # Build a mapping from every possible block to the byte
        # that generates it.
        possible_blocks = self._get_possible_blocks()
        matching_byte = possible_blocks[target_block]
        self._update_input_strings(matching_byte)
        return matching_byte
        
    def _decrypt_string(self):
        length = self._discover_string_length()
        string = str()
        # The test_string is the string used to invoke the oracle.
        # Always has block_size - 1 bytes. The remaining byte will be
        # completed one byte at a time for every possible value.
        self.test_string = 'X'*(self.block_size-1)
        # The input_string is used to get the actual byte we are targeting
        # each time.
        self.input_string = self.test_string
        for byte_index in xrange(length):
            # +1 in order to simplify math inside.
            string += self._discover_byte(1+byte_index, string)
        return string
        
    def value(self):
        self.block_size = self._discover_block_size()
        self._ensure_ecb_mode()
        return self._decrypt_string()