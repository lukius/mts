from Crypto.Hash import SHA256 as _SHA256

from common.hash import HashFunction


class SHA256(HashFunction):
    
    @classmethod
    def get_OID(cls):
        return '\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
    
    def hash(self, message):
        # TODO: implement custom SHA256.
        return _SHA256.new(message).digest()