import socket

from common.key_exchange.protocol import KeyExchangeProtocol,\
                                         KeyExchangeProtocolServer


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
        self.g = self._receive_int(socket=self.client_socket)
        self.p = self._receive_int(socket=self.client_socket)
        self.A = self._receive_int(socket=self.client_socket)
        self._init_diffie_hellman_from(self.p, self.g)

    def _receive_public_key_from_client(self):
        self.B = self._receive_int(socket=self.server_socket)
    
    def _inject_parameters_to_client(self):
        self._send(self.g, socket=self.server_socket)
        self._send(self.p, socket=self.server_socket)
        self._send(self.p, socket=self.server_socket)
        
    def _inject_client_public_key_to_server(self):
        self._send(self.p, socket=self.client_socket)
        
    def _send_message_to_client(self, iv_and_message):
        self._send(iv_and_message, socket=self.server_socket)

    def _send_message_to_server(self, iv_and_message):
        self._send(iv_and_message, socket=self.client_socket)
        
    def _decrypt_message(self, iv_and_message, secret):
        iv = iv_and_message[:self.BLOCK_SIZE]
        self._init_cipher_from(secret, iv)
        message = iv_and_message[self.BLOCK_SIZE:]
        return self.cipher.decrypt(message, mode=self.cipher_mode).bytes()
    
    def stop(self):
        KeyExchangeProtocolServer.PORT -= 1
        
    def _run(self):
        self._wait_for_client_and_connect()
        # Receive p, g and A from server; ignore A.
        self._receive_parameters_from_server()
        # Inject our parameters to the other party.
        self._inject_parameters_to_client()
        # Receive B from client.
        self._receive_public_key_from_client()
        # Inject custom B to server.
        self._inject_client_public_key_to_server()
        # Receive and relay encrypted message + IV (from server)
        iv_and_message = self._receive(socket=self.client_socket)
        self._send_message_to_client(iv_and_message)
        # Secret is fixed to 0 since p**n = 0 mod p for any n.
        self.message = self._decrypt_message(iv_and_message, secret=0)
        # Receive and relay encrypted message + IV (from client)
        iv_and_message = self._receive(socket=self.server_socket)
        self._send_message_to_server(iv_and_message) 