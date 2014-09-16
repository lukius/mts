import struct


class HashFunction(object):
    
    @classmethod
    def get_OID(cls):
        # AlgorithmIdentifier OID (used for PKCS#1 v1.5 digital signature).
        raise NotImplementedError
    
    def hash(self, message):
        raise NotImplementedError