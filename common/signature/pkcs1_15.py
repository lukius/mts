from Crypto.Util.asn1 import DerOctetString, DerSequence, DerNull

from common.signature import DigitalSignatureScheme
from common.ciphers.pubkey.rsa import RSA
from common.hash.sha1 import SHA1
from common.tools.misc import ByteSize
from common.tools.padders import LeftPadder


class PKCS1_15DigitalSignature(DigitalSignatureScheme):
    
    def __init__(self, hash_function=SHA1):
        DigitalSignatureScheme.__init__(self)
        self.hash_function = hash_function()
        self.rsa = self._RSA()
        self.public_key = self.rsa.get_public_key()
        self.e, self.n = self.public_key
        self.n_size = ByteSize(self.n).value()
        
    def _RSA(self):
        return RSA()
        
    def _decrypt(self, signature):
        decrypted_block = self.rsa.encrypt(signature)
        return LeftPadder(decrypted_block).value(self.n_size, char='\0')
    
    def _encode(self, message):
        hash_oid = self.hash_function.get_OID()
        digest = self.hash_function.hash(message)
        der_digest = DerOctetString(digest).encode()
        der_null = DerNull().encode()
        der_sequence = DerSequence([hash_oid, der_null]).encode()
        hash_info = DerSequence([der_sequence, der_digest]).encode()
        hash_size = len(hash_info)
        padding = '\xff'*(self.n_size - hash_size - 3)
        return '\x00\x01' + padding + '\0' + hash_info
    
    def sign(self, message):
        encoded_message = self._encode(message)
        # Decrypt in order to use the private key.
        return self.rsa.decrypt(encoded_message)
    
    def verify(self, message, signature):
        encoded_message = self._encode(message)
        block = self._decrypt(signature)
        return encoded_message == block