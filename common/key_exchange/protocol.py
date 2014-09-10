import socket
import threading

from common.ciphers.block.aes import AES
from common.ciphers.block.modes import CBC
from common.hash.sha1 import SHA1
from common.key_exchange.diffie_hellman import DiffieHellman
from common.tools.converters import BytesToInt, IntToBytes
from common.tools.misc import Concatenation, RandomByteGenerator


class KeyExchangeProtocol(object):
    
    MAX_INT = DiffieHellman.MAX_INT
    LENGTH_FIELD_SIZE = 4
    BLOCK_SIZE = 16
    
    STATUS_RUNNING = 0
    STATUS_OK = 1
    STATUS_ERROR = 2
    
    def __init__(self):
        self.socket = socket.socket()
        self.thread = threading.Thread(target=self._run)
        self.status = self.STATUS_RUNNING
        
    def _init_diffie_hellman_from(self, p, g):
        self.diffie_hellman = DiffieHellman(p, g)
        
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
        
    def _receive(self, socket=None):
        socket = socket if socket is not None else self.socket
        size_bytes = socket.recv(self.LENGTH_FIELD_SIZE)
        size = BytesToInt(size_bytes).value()
        return socket.recv(size)
    
    def _receive_int(self, socket=None):
        integer = self._receive(socket)
        return int(integer)    
    
    def _send(self, *values, **kwargs):
        message = Concatenation(map(str, values)).value()
        size_bytes = IntToBytes(len(message)).value(self.LENGTH_FIELD_SIZE)
        socket = kwargs['socket'] if 'socket' in kwargs and kwargs['socket'] is not None else self.socket
        socket.send(size_bytes + message)
        
    def get_status(self):
        return self.status
        
    def start(self):
        self.thread.start()
        
    def stop(self):
        self.thread.join()


class KeyExchangeProtocolServer(KeyExchangeProtocol):
    
    ADDRESS = '127.0.0.1'
    PORT = 20100
    P = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020'+\
        'bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe135'+\
        '6d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5'+\
        'a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55'+\
        'd39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966'+\
        'd670c354e4abc9804f1746c08ca237327ffffffffffffffff'
    G = 3
    MESSAGE = 'PERRO RATA'
    
    def __init__(self):
        KeyExchangeProtocol.__init__(self)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.ADDRESS, self.PORT))
        self.socket.listen(1)
        self.p = int(self.P, 16)
        self._init_diffie_hellman_from(self.p, self.G)
        
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
        self.socket, _ = self.socket.accept()
        self._send_parameters()
        B = self._receive_int()
        secret = self.diffie_hellman.get_secret_from(B)
        message = self._build_message_from(secret)
        self._send(message)
        self._assert_proper_reception()
        

class KeyExchangeProtocolClient(KeyExchangeProtocol):

    def __init__(self):
        KeyExchangeProtocol.__init__(self)
        self.server_address = KeyExchangeProtocolServer.ADDRESS
        self.server_port = KeyExchangeProtocolServer.PORT
    
    def _connect(self):
        self.socket.connect((self.server_address, self.server_port))
        
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