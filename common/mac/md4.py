from common.hash.md4 import MD4
from common.mac import MessageAuthenticationCode


class MD4BasedMAC(MessageAuthenticationCode):
    
    def value(self, message):
        return MD4().hash(self.key + message)