from common.mac import MessageAuthenticationCode


class HashBasedMAC(MessageAuthenticationCode):
    
    def __init__(self, key, hash_function):
        MessageAuthenticationCode.__init__(self, key)
        self.hash_function = hash_function()
    
    def value(self, message):
        return self.hash_function.hash(self.key + message)