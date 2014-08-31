class MessageAuthenticationCode(object):
    
    def __init__(self, key):
        self.key = key
        
    def validate(self, message, mac):
        actual_mac = self.value(message)
        return mac == actual_mac        
        
    def value(self, message):
        raise NotImplementedError