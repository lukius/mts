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
        
    def get_message(self):
        pass
        
    def _init_server_socket(self):
        self.server_socket = socket.socket()
        self.server_socket.bind((self.SERVER_ADDRESS, self.SERVER_PORT))
        self.server_socket.listen(1)
        KeyExchangeProtocolServer.PORT += 1
        
    def _wait_for_client_and_connect(self):
        self.server_socket, _ = self.server_socket.accept()
        self.client_socket.connect((self.SERVER_ADDRESS, self.SERVER_PORT+1))
        
    def _run(self):
        self._wait_for_client_and_connect()
        # TODO: complete...


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