from common.attacks.xor import RepeatingKeyXORDecrypter
from common.base64 import Base64Decoder
from common.ciphers.block.aes import AES
from common.ciphers.block.modes import CTR
from common.challenge import MatasanoChallenge
from common.tools import Concatenation, FileLines, RandomByteGenerator


class FixedNonceCTRDecrypter(object):
        
    def decrypt(self, ciphertexts):
        ciphertext = ConcatenationAfterTruncation(ciphertexts).value()
        return RepeatingKeyXORDecrypter().decrypt(ciphertext)


class ConcatenationAfterTruncation(object):

    def __init__(self, strings):
        self.strings = strings

    def value(self):
        min_length = min(map(len, self.strings))
        strings = [string[:min_length] for string in self.strings]
        return Concatenation(strings).value()


class Set3Challenge4(MatasanoChallenge):
    
    FILE = 'set3/data/20.txt'
    ANSWER_FILE = 'set3/data/20ans.txt'
    BLOCK_SIZE = 16
    
    def expected_value(self):
        strings = FileLines(self.ANSWER_FILE).value()
        return ConcatenationAfterTruncation(strings).value()
    
    def _encrypt(self, plaintexts):
        key = RandomByteGenerator().value(self.BLOCK_SIZE)
        aes = AES(key)
        return map(lambda text: aes.encrypt(text, mode=CTR(nonce=0)).bytes(),
                   plaintexts)
    
    def value(self):
        strings = FileLines(self.FILE).value()
        decoder = Base64Decoder()
        plaintexts = map(lambda string: decoder.decode(string), strings)
        ciphertexts = self._encrypt(plaintexts)
        return FixedNonceCTRDecrypter().decrypt(ciphertexts)