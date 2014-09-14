import random

from common.key_exchange.protocols.srp import SecureRemotePasswordClient,\
                                              SecureRemotePasswordServer
    
    
class SimplifiedSRPClient(SecureRemotePasswordClient):
    
    def _compute_u(self):
        return self.u
    
    def _compute_S_from(self, x):
        exponent = self.a + self.u*x
        S = self.modexp.value(self.B, exponent)
        return self._from_int(S)
    
    def _receive_parameters(self):
        SecureRemotePasswordClient._receive_parameters(self)
        self.u = self._receive_int()
    

class SimplifiedSRPServer(SecureRemotePasswordServer):
    
    def _init_state(self):
        SecureRemotePasswordServer._init_state(self)
        self.u = random.randint(1, SecureRemotePasswordServer.MAX_INT)

    def _compute_B(self):
        return self.modexp.value(self.G, self.b)
    
    def _send_parameters(self):
        SecureRemotePasswordServer._send_parameters(self)
        self._send(self.u)
        
    def _compute_key(self):
        S = self._compute_S_from(self.u)
        self._set_key_from(S)