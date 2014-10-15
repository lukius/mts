from common.attacks.hash.md4 import MD4CollisionGenerator
from common.challenge import MatasanoChallenge
from common.hash.md4 import MD4
from common.tools.misc import RandomByteGenerator


class Set7Challenge55(MatasanoChallenge):
    
    MESSAGE = RandomByteGenerator().value(MD4.block_size())
    
    def validate(self):
        md4 = MD4()
        collisions = MD4CollisionGenerator().value(self.MESSAGE)
        return md4.hash(collisions[0]) == md4.hash(collisions[1])