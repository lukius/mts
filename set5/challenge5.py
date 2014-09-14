from common.challenge import MatasanoChallenge
from common.key_exchange.protocols.srp import SecureRemotePassword,\
                                              SecureRemotePasswordClient,\
                                              SecureRemotePasswordServer


class SRPAuthBypassWithZeroKey(SecureRemotePasswordClient):
    
    def __init__(self):
        # Initialize with empty email/password (we don't need them).
        SecureRemotePasswordClient.__init__(self, str(), str())
    
    def _send_A(self):
        # Sending any multiple of the underlying prime will have the same
        # effect: the key computed by the server will be zero.
        self._send(0)
        
    def _compute_key_from(self, B):
        S = self._from_int(0) 
        self._set_key_from(S)


class Set5Challenge5(MatasanoChallenge):
    
    EMAIL = 'foo@bar.baz'
    PASSWORD = 'at4r0rrep'
    
    def validate(self):
        client = SRPAuthBypassWithZeroKey()
        server = SecureRemotePasswordServer(self.EMAIL, self.PASSWORD)
        
        server.start()
        client.start()
        client.stop()
        server.stop()

        return client.get_status() == SecureRemotePassword.STATUS_OK and\
               server.get_status() == SecureRemotePassword.STATUS_OK