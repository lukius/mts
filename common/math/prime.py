from Crypto.Util import number


class RandPrime(object):
    
    DEFAULT_BITS = 1024
    
    def value(self, n=None):
        # Compute a random n-bit prime number. 
        # TODO: implement Miller-Rabin in order to test primality.
        if n is None:
            n = self.DEFAULT_BITS
        return number.getPrime(n)