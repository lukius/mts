from common.challenge import MatasanoChallenge
from common.key_exchange.protocols.srp import SecureRemotePassword,\
                                              SecureRemotePasswordClient,\
                                              SecureRemotePasswordServer


class Set5Challenge4(MatasanoChallenge):
    
    EMAIL = 'foo@bar.baz'
    PASSWORD = 'at4r0rrep'
    
    def validate(self):
        client = SecureRemotePasswordClient(self.EMAIL, self.PASSWORD)
        server = SecureRemotePasswordServer(self.EMAIL, self.PASSWORD)
        
        server.start()
        client.start()
        client.stop()
        server.stop()

        return client.get_status() == SecureRemotePassword.STATUS_OK and\
               server.get_status() == SecureRemotePassword.STATUS_OK