from common.ciphers.block.aes import AES
from common.ciphers.block.modes import CBC
from common.hash.sha1 import SHA1
from common.tools.converters import IntToBytes
from common.tools.misc import RandomByteGenerator
from common.key_exchange.protocols import KeyExchangeProtocol,\
                                          KeyExchangeProtocolServer,\
                                          KeyExchangeProtocolClient


class KeyExchangeToyProtocol(KeyExchangeProtocol):
    
    def _init_cipher_from(self, secret, iv=None):
        secret_bytes = IntToBytes(secret).value()
        key = SHA1().hash(secret_bytes)[:self.BLOCK_SIZE]
        self.iv = RandomByteGenerator().value(self.BLOCK_SIZE) if iv is None\
                  else iv
        self.cipher = AES(key)
        self.cipher_mode = CBC(iv=self.iv)
        
    def _send_public_key(self):
        key = self.diffie_hellman.get_public_key()
        self._send(key)         
        

class KeyExchangeToyProtocolServer(KeyExchangeToyProtocol,
                                   KeyExchangeProtocolServer):
    
    MESSAGE = 'PERRO RATA'
    
    def _send_parameters(self):
        self._send(self.G)
        self._send(self.p)
        self._send_public_key()
        
    def _assert_proper_reception(self):
        message = self._receive()
        decrypted_message = self.cipher.decrypt(message,
                                                mode=self.cipher_mode).bytes()
        self.status = self.STATUS_ERROR\
                      if decrypted_message[::-1] != self.MESSAGE\
                      else self.STATUS_OK
    
    def _build_message_from(self, secret):
        self._init_cipher_from(secret)
        encrypted_message = self.cipher.encrypt(self.MESSAGE,
                                                mode=self.cipher_mode)
        return self.iv + encrypted_message.bytes()
        
    def _run(self):
        self._accept_connection()
        self._send_parameters()
        B = self._receive_int()
        secret = self.diffie_hellman.get_secret_from(B)
        message = self._build_message_from(secret)
        self._send(message)
        self._assert_proper_reception()
        

class KeyExchangeToyProtocolClient(KeyExchangeToyProtocol,
                                   KeyExchangeProtocolClient):

    def _receive_message(self, A):
        try:
            secret = self.diffie_hellman.get_secret_from(A)
            iv_and_message = self._receive()
            iv = iv_and_message[:self.BLOCK_SIZE]
            self._init_cipher_from(secret, iv)
            message = iv_and_message[self.BLOCK_SIZE:]
        except Exception:
            self.status = self.STATUS_ERROR
        else:
            return self.cipher.decrypt(message, mode=self.cipher_mode).bytes()
        
    def _receive_parameters(self):
        g = self._receive_int()
        p = self._receive_int()
        A = self._receive_int()
        self._init_diffie_hellman_from(p, g)
        return p, g, A
    
    def _reencrypt_reversed_and_send(self, message):
        message = message[::-1]
        encrypted_message = self.cipher.encrypt(message, mode=self.cipher_mode)
        self._send(encrypted_message)
    
    def _run(self):
        self._connect()
        _, _, A = self._receive_parameters()
        self._send_public_key()
        message = self._receive_message(A)
        if self.status != self.STATUS_ERROR:
            self._reencrypt_reversed_and_send(message)
            self.status = self.STATUS_OK