from common.attacks.hash.nostradamus import NostradamusAttack
from common.challenge import MatasanoChallenge
from common.hash.tools.build import BasicHashFunctionFactory
from common.tools.misc import RandomByteGenerator


class Set7Challenge6(MatasanoChallenge):
    
    LENGTH = 50
    PREFIX = RandomByteGenerator().value(LENGTH)
    
    def validate(self):
        hash_function = BasicHashFunctionFactory.build(16)
        attack = NostradamusAttack(hash_function)
        prediction = attack.prediction()
        message = attack.for_prefix(self.PREFIX)
        return hash_function().hash(message) == prediction