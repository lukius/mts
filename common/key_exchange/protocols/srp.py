import random

from common.key_exchange.protocols import KeyExchangeProtocol,\
                                          KeyExchangeProtocolClient,\
                                          KeyExchangeProtocolServer
from common.tools.misc import RandomByteGenerator
from common.hash.sha256 import SHA256
from common.tools.converters import BytesToInt, IntToBytes
from common.math.modexp import ModularExp
from common.mac.hmac import HMAC
    
    
class SecureRemotePassword(KeyExchangeProtocol):
    
    K = 3
    
    MESSAGE_OK = 'OK'
    MESSAGE_ERROR = 'ERROR'
    
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.sha256 = SHA256()
        self.modexp = ModularExp(self.p)
        self._init_state()
        
    def _compute_u_from(self, A, B):
        A_bytes = self._from_int(A)
        B_bytes = self._from_int(B)
        hash_string = self.sha256.hash(A_bytes + B_bytes)
        return self._to_int(hash_string)
    
    def _set_key_from(self, S):
        self.key = self.sha256.hash(S)  
        
    def _to_int(self, byte_string):
        return BytesToInt(byte_string).value()
    
    def _from_int(self, integer):
        return IntToBytes(integer).value()


class SecureRemotePasswordClient(SecureRemotePassword, KeyExchangeProtocolClient):
    
    def __init__(self, email, password):
        KeyExchangeProtocolClient.__init__(self)
        SecureRemotePassword.__init__(self, email, password)    
    
    def _init_state(self):
        self.a = random.randint(1, self.MAX_INT)
    
    def _send_A(self):
        self.A = self.modexp.value(self.G, self.a)
        self._send(self.A)
        
    def _compute_S_from(self, B, x, u):
        base = B - (self.K * self.modexp.value(self.G, x))
        exponent = self.a + u*x
        S = self.modexp.value(base, exponent)
        return self._from_int(S)
    
    def _compute_key_from(self, B):
        u = self._compute_u_from(self.A, B)
        hashed_password = self.sha256.hash(self.salt + self.password)
        integer = self._to_int(hashed_password)
        S = self._compute_S_from(B, integer, u)
        self._set_key_from(S)
    
    def _send_hash(self):
        hmac = HMAC(self.key, SHA256).value(self.salt)
        self._send(hmac)
    
    def _receive_result(self):
        message = self._receive()
        self.status = self.STATUS_OK if message == self.MESSAGE_OK\
                      else self.STATUS_ERROR
    
    def _run(self):
        self._connect()
        self._send_A()
        self.salt = self._receive()
        B = self._receive_int()
        self._compute_key_from(B)
        self._send_hash()
        self._receive_result()


class SecureRemotePasswordServer(SecureRemotePassword, KeyExchangeProtocolServer):

    def __init__(self, email, password):
        KeyExchangeProtocolServer.__init__(self)
        SecureRemotePassword.__init__(self, email, password)
    
    def _init_state(self):
        self.b = random.randint(1, self.MAX_INT)
        self.salt = RandomByteGenerator().value()
        hashed_password = self.sha256.hash(self.salt + self.password)
        integer = self._to_int(hashed_password)
        self.v = self.modexp.value(self.G, integer)
    
    def _compute_B(self):
        integer = self.modexp.value(self.G, self.b)
        return self.K*self.v + integer
    
    def _send_validation_result(self, received_hmac):
        hmac = HMAC(self.key, SHA256).value(self.salt)
        if hmac == received_hmac:
            result = self.MESSAGE_OK
            self.status = self.STATUS_OK
        else:
            result = self.MESSAGE_ERROR
            self.status = self.STATUS_ERROR
        self._send(result)
    
    def _send_salt_and_B(self):
        self._send(self.salt)
        self.B = self._compute_B()
        self._send(self.B)
        
    def _compute_S_from(self, A, u):
        base = A * self.modexp.value(self.v, u)
        S = self.modexp.value(base, self.b)
        return self._from_int(S)
        
    def _compute_key_from(self, A):
        u = self._compute_u_from(A, self.B)
        S = self._compute_S_from(A, u)
        self._set_key_from(S)
    
    def _run(self):
        self._accept_connection()
        A = self._receive_int()
        self._send_salt_and_B()
        self._compute_key_from(A)
        hmac = self._receive()
        self._send_validation_result(hmac)