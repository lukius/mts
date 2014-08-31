from Crypto.Hash import SHA

from common.mac import MessageAuthenticationCode


class SHA1BasedMAC(MessageAuthenticationCode):
    
    def value(self, message):
        return SHA.new(self.key + message).digest()