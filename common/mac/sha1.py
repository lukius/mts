from common.hash.sha1 import SHA1
from common.mac import MessageAuthenticationCode


class SHA1BasedMAC(MessageAuthenticationCode):
    
    def value(self, message):
        return SHA1().hash(self.key + message)