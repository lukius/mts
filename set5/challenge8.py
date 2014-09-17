from common.challenge import MatasanoChallenge
from common.ciphers.pubkey.rsa import FixedERSA
from common.math.invmod import ModularInverse
from common.tools.converters import IntToBytes, BytesToInt
from common.tools.misc import Product
from common.math.root import NthRoot


class RSABroadcastAttack(object):
    
    def __init__(self, public_keys):
        self.moduli = map(lambda pubkey: pubkey[1], public_keys)
        self.n = len(self.moduli)
        
    def _modular_inverse(self, integer, modulus):
        return ModularInverse(modulus).value(integer)
        
    def _compute_moduli_products(self):
        def moduli_product(i):
            moduli = self.moduli[:i] + self.moduli[i+1:]
            return Product(moduli).value()
        
        return [moduli_product(i) for i in range(len(self.moduli))]
    
    def _compute_modular_inverses_for(self, products):
        return [self._modular_inverse(products[i], self.moduli[i])\
                for i in range(len(self.moduli))]
        
    def _compute_CRT_result_from(self, ciphertexts, products, inverses):
        # TODO: implement resolution of systems of linear congruences through
        # CRT.
        moduli_product = Product(self.moduli).value()
        result = sum([ciphertexts[i] * products[i] * inverses[i]\
                      for i in range(self.n)])
        return result % moduli_product
    
    def decrypt(self, ciphertexts):
        ciphertexts = map(lambda ciphertext: BytesToInt(ciphertext).value(),
                          ciphertexts)
        products = self._compute_moduli_products()
        inverses = self._compute_modular_inverses_for(products)
        crt_result = self._compute_CRT_result_from(ciphertexts, products,
                                                   inverses)
        nth_root = NthRoot(self.n).value(crt_result)
        return IntToBytes(nth_root).value()


class Set5Challenge8(MatasanoChallenge):
    
    PLAINTEXT = 'Vos tambien la tenes adentro.'
    E = 3
    
    def expected_value(self):
        return self.PLAINTEXT
    
    def value(self):
        rsa_instances = [FixedERSA(e=self.E) for _ in range(self.E)]
        ciphertexts = map(lambda rsa: rsa.encrypt(self.PLAINTEXT),
                          rsa_instances)
        public_keys = map(lambda rsa: rsa.get_public_key(), rsa_instances)
        attack = RSABroadcastAttack(public_keys)
        return attack.decrypt(ciphertexts)