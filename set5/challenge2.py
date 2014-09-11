import socket

from common.challenge import MatasanoChallenge
from common.key_exchange.protocol import KeyExchangeProtocolServer,\
                                         KeyExchangeProtocolClient,\
                                         KeyExchangeProtocol


class KeyExchangeProtocolMITMAttack(KeyExchangeProtocol):
    
    SERVER_ADDRESS = KeyExchangeProtocolServer.ADDRESS
    SERVER_PORT = KeyExchangeProtocolServer.PORT
    
    def __init__(self):
        KeyExchangeProtocol.__init__(self)
        self.client_socket = socket.socket()
        self._init_server_socket()
        self.start()
        
    def _init_server_socket(self):
        self.server_socket = socket.socket()
        self.server_socket.bind((self.SERVER_ADDRESS, self.SERVER_PORT))
        self.server_socket.listen(1)
        KeyExchangeProtocolServer.PORT += 1

    def get_message(self):
        return self.message

    def _wait_for_client_and_connect(self):
        self.server_socket, _ = self.server_socket.accept()
        self.client_socket.connect((self.SERVER_ADDRESS, self.SERVER_PORT+1))

    def _receive_parameters_from_server(self):
        g = self._receive_int(socket=self.client_socket)
        p = self._receive_int(socket=self.client_socket)
        A = self._receive_int(socket=self.client_socket)
        self._init_diffie_hellman_from(p, g)
        return p, g, A
    
    def _inject_parameters_to_client(self, g, p):
        self._send(g, socket=self.server_socket)
        self._send(p, socket=self.server_socket)
        self._send(p, socket=self.server_socket)         
        
    def _decrypt_message(self, iv_and_message):
        iv = iv_and_message[:self.BLOCK_SIZE]
        # Secret is fixed to 0 since p**n = 0 mod p for any n.
        self._init_cipher_from(0, iv)
        message = iv_and_message[self.BLOCK_SIZE:]
        return self.cipher.decrypt(message, mode=self.cipher_mode).bytes()    
        
    def _run(self):
        self._wait_for_client_and_connect()
        # Receive p, g and A from server; ignore A.
        p, g, _ = self._receive_parameters_from_server()
        # Inject our parameters to the other party.
        self._inject_parameters_to_client(g, p)
        # Receive B from client and ignore it.
        self._receive_int(socket=self.server_socket)
        # Inject custom B to server.
        self._send(p, socket=self.client_socket)
        # Receive and relay encrypted message + IV (from server)
        iv_and_message = self._receive(socket=self.client_socket)
        self._send(iv_and_message, socket=self.server_socket)
        self.message = self._decrypt_message(iv_and_message)
        # Receive and relay encrypted message + IV (from client)
        iv_and_message = self._receive(socket=self.server_socket)
        self._send(iv_and_message, socket=self.client_socket)        


class Set5Challenge2(MatasanoChallenge):
    
    def validate(self):
        client = KeyExchangeProtocolClient()
        attack = KeyExchangeProtocolMITMAttack()
        server = KeyExchangeProtocolServer()
        
        server.start()
        client.start()
        client.stop()
        server.stop()
        
        message = attack.get_message()
        
        return message == KeyExchangeProtocolServer.MESSAGE and\
               client.get_status() == KeyExchangeProtocol.STATUS_OK and\
               server.get_status() == KeyExchangeProtocol.STATUS_OK 