from Crypto.Hash import SHA256 as _SHA256

from common.hash import HashFunction


class SHA256(HashFunction):
    
    def hash(self, message):
        # TODO: implement custom SHA256.
        return _SHA256.new(message).digest()