import random

from common.challenge import MatasanoChallenge
from common.ciphers.block.cipher import AES
from common.ciphers.block.modes import ECB, CBC
from common.tools import RandomByteGenerator


class RandomECB_CBCEncrypter(object):
    
    def __init__(self, block_size):
        self.block_size = block_size
        self.random_generator = RandomByteGenerator()
    
    def get_mode(self):
        # To use after encryption in order to confirm that the oracle works.
        return self.mode.name()
    
    def _prepare_plaintext(self, plaintext):
        header = self.random_generator.value(random.randint(5,10))
        footer = self.random_generator.value(random.randint(5,10))
        return '%s%s%s' % (header, plaintext, footer)
    
    def _get_random_mode(self):
        if random.random() >= 0.5:
            mode = ECB(block_size=self.block_size)
        else:
            random_iv = self.random_generator.value(self.block_size)
            mode = CBC(iv=random_iv, block_size=self.block_size)
        return mode
    
    def encrypt(self, plaintext):
        plaintext = self._prepare_plaintext(plaintext)
        key = self.random_generator.value(self.block_size)
        self.mode = self._get_random_mode()
        return AES(key).encrypt(plaintext, mode=self.mode)
    
    
class ECB_CBCDetectionOracle(object):
    
    BLOCKS = 20

    def __init__(self, encrypter):
        self.encrypter = encrypter
        self.block_size = encrypter.block_size

    def _all_equal(self, blocks):
        return len(set(blocks)) == 1
    
    def _build_chosen_plaintext(self):
        return 'X'*self.block_size*self.BLOCKS
    
    def value(self):
        plaintext = self._build_chosen_plaintext()
        ciphertext = self.encrypter.encrypt(plaintext)
        blocks = [ciphertext[i:i+self.block_size]
                  for i in range(0, len(ciphertext), self.block_size)]
        # First and last blocks include random, non-controlled data.
        if self._all_equal(blocks[1:-2]):
            mode = ECB.name()
        else:
            mode = CBC.name()
        return mode


class Set2Challenge3(MatasanoChallenge):
    
    BLOCK_SIZE = 16
    
    def __init__(self):
        MatasanoChallenge.__init__(self)
        self.encrypter = RandomECB_CBCEncrypter(self.BLOCK_SIZE)
        self.oracle = ECB_CBCDetectionOracle(self.encrypter)
    
    def expected_value(self):
        return self.encrypter.get_mode()

    def value(self):
        return self.oracle.value()