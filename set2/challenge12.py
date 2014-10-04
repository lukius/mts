from common.challenge import MatasanoChallenge
from common.ciphers.block.tools import ECBDecrypter, ECBEncryptionOracle
        

class Set2Challenge12(MatasanoChallenge):

    def expected_value(self):
        return 'Rollin\' in my 5.0\n' +\
               'With my rag-top down so my hair can blow\n' +\
               'The girlies on standby waving just to say hi\n' +\
               'Did you stop? No, I just drove by\n'

    def value(self):
        oracle = ECBEncryptionOracle()
        return ECBDecrypter(oracle).value()