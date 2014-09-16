class DigitalSignatureScheme(object):
    
    def get_public_key(self):
        return self.public_key
    
    def sign(self, messsage):
        raise NotImplementedError
    
    def verify(self, message, signature):
        raise NotImplementedError
        