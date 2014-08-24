from common.challenge import MatasanoChallenge
from common.random.generators import MersenneTwister


class Set3Challenge5(MatasanoChallenge):
    
    SEED = 1
    INTS = 5
    
    def expected_value(self):
        # Taken from output of other implementations found on the Internet.
        return [1791095845, 4282876139, 3093770124, 4005303368, 491263]
    
    def value(self):
        prng = MersenneTwister(seed=self.SEED)
        return [prng.rand() for _ in range(self.INTS)]
        