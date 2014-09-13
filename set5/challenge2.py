from common.attacks.key_exchange import KeyExchangeProtocolMITMAttack
from common.challenge import MatasanoChallenge
from common.key_exchange.protocol import KeyExchangeProtocolServer,\
                                         KeyExchangeProtocolClient,\
                                         KeyExchangeProtocol


class Set5Challenge2(MatasanoChallenge):
    
    def validate(self):
        client = KeyExchangeProtocolClient()
        attack = KeyExchangeProtocolMITMAttack()
        server = KeyExchangeProtocolServer()
        
        server.start()
        client.start()
        client.stop()
        server.stop()
        attack.stop()
        
        message = attack.get_message()
        
        return message == KeyExchangeProtocolServer.MESSAGE and\
               client.get_status() == KeyExchangeProtocol.STATUS_OK and\
               server.get_status() == KeyExchangeProtocol.STATUS_OK 