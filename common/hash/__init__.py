import struct

from common.tools.converters import BytesToInt


class HashFunction(object):
    
    @classmethod
    def get_OID(cls):
        # AlgorithmIdentifier OID (used for PKCS#1 v1.5 digital signature).
        raise NotImplementedError
    
    def hash(self, message):
        raise NotImplementedError
    
    def int_hash(self, message):
        hash_bytes = self.hash(message)
        return BytesToInt(hash_bytes).value()