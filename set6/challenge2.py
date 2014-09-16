from common.challenge import MatasanoChallenge


class EEquals3RSASignatureForger(object):
    
    def __init__(self, public_key):
        self.e, self.n = public_key
    
    def forge(self, string):
        pass


class Set6Challenge2(MatasanoChallenge):

    STRING = 'hi mom'
    
    def validate(self):
        # TBC...
        pass
        