import random

from common.hash.md4 import MD4
from common.tools.misc import Concatenation


class MD4CollisionGenerator(object):
    
    # Based on "Cryptanalysis of the Hash Functions MD4 and RIPEMD" by
    # Wang et al.
    
    MULTISTEP_ITERATIONS = 100
    
    def __init__(self):
        self.md4 = MD4()
        
    def _rotate_right(self, integer, count):
        size = self.md4.register_size()
        mask = self.md4.mask
        return ((integer >> count) | (integer << (size - count))) & mask
    
    def _build_message_from(self, words):
        endianness = self.md4.endianness()
        words = map(lambda word: endianness.from_int(word, 4).value(),
                                 words)
        return Concatenation(words).value()

    def _rand_word(self):
        return random.randint(0, self.md4.mask)
    
    def _set_bits(self, integer, bits):
        for index, value in bits.items():
            bit = 1 << (index-1)
            if value == 0:
                integer &= self.md4._not(bit)
            elif value == 1:
                integer |= bit
        return integer
    
    def _get_bit(self, integer, index):
        index = index-1
        return (integer & (1 << index)) >> index
    
    def _get_bits(self, integer, indices):
        return map(lambda index: self._get_bit(integer, index),
                   indices)
    
    def _multistep_modifications(self, words1, words2, state1, state2):
        a, b, c, d = self.md4.initial_state()
        F = self.md4.F
        G = self.md4.G
        z = 0x5a827999
        
        for k in range(self.MULTISTEP_ITERATIONS):
            # a5,19 = c4,19, a5,26 = 1, a5,27 = 0, a5,29 = 1, a5,32 = 1
            state1[16] = self._set_bits(self._rand_word(), {26: 1, 27: 0, 29: 1, 32: 1,
                                                            19: self._get_bit(state1[14], 19)})
            state2[16] = (state1[16] + (1 << 25) - (1 << 28) - (1 << 31)) & self.md4.mask
            
            words1[0] = (self._rotate_right(state1[16], 3) - G(state1[15], state1[14], state1[13]) - state1[12] - z) & self.md4.mask
            words2[0] = (self._rotate_right(state2[16], 3) - G(state2[15], state2[14], state2[13]) - state2[12] - z) & self.md4.mask
            if words2[0] != words1[0]:
                continue
            
            # Restore conditions from first round.
            state1[0] = self.md4._rotate_left(F(b, c, d) + a + words1[0] & self.md4.mask,  3)
            if self._get_bit(state1[0], 7) != self._get_bit(b, 7):
                continue            
            state2[0] = state1[0]                   
            
            words1[1] = (self._rotate_right(state1[1], 7) - d - F(state1[0], b, c)) & self.md4.mask 
            words2[1] = (self._rotate_right(state2[1], 7) - d - F(state2[0], b, c)) & self.md4.mask 
            if words2[1] - words1[1] != (1 << 31):
                continue
            
            words1[2] = (self._rotate_right(state1[2], 11) - c - F(state1[1], state1[0], b)) & self.md4.mask 
            words2[2] = (self._rotate_right(state2[2], 11) - c - F(state2[1], state2[0], b)) & self.md4.mask 
            if words2[2] - words1[2] != -(1 << 28) + (1 << 31):
                continue
            
            words1[3] = (self._rotate_right(state1[3], 19) - b - F(state1[2], state1[1], state1[0])) & self.md4.mask 
            words2[3] = (self._rotate_right(state2[3], 19) - b - F(state2[2], state2[1], state2[0])) & self.md4.mask 
            if words1[3] != words2[3]:
                continue
            
            words1[4] = (self._rotate_right(state1[4], 3) - state1[0] - F(state1[3], state1[2], state1[1])) & self.md4.mask 
            words2[4] = (self._rotate_right(state2[4], 3) - state2[0] - F(state2[3], state2[2], state2[1])) & self.md4.mask 
            if words1[4] != words2[4]:
                continue
            
            break

        if k == self.MULTISTEP_ITERATIONS-1:
            return False
        
        for k in range(self.MULTISTEP_ITERATIONS):
            # d5,19 = a5,19, d5,26 = b4,26, d5,27 = b4,27, d5,29 = b4,29,
            # d5,32 = b4,32
            state1[17] = self._set_bits(self._rand_word(), {19: self._get_bit(state1[16], 19),
                                                            26: self._get_bit(state1[15], 26),
                                                            27: self._get_bit(state1[15], 27),
                                                            29: self._get_bit(state1[15], 29),
                                                            32: self._get_bit(state1[15], 32)})
            state2[17] = state1[17]
            
            words1[4] = (self._rotate_right(state1[17], 5) - G(state1[16], state1[15], state1[14]) - state1[13] - z) & self.md4.mask
            words2[4] = (self._rotate_right(state2[17], 5) - G(state2[16], state2[15], state2[14]) - state2[13] - z) & self.md4.mask
            if words2[4] != words1[4]:
                continue
            
            # Restore conditions from first round.
            state1[4] = self.md4._rotate_left(F(state1[3], state1[2], state1[1]) + state1[0] + words1[4] & self.md4.mask,  3)
            if self._get_bits(state1[4], [8, 11, 26, 14]) != [1, 1, 0, self._get_bit(state1[3], 14)]:
                continue
            state2[4] = state1[4]                   
            
            words1[5] = (self._rotate_right(state1[5], 7) - state1[1] - F(state1[4], state1[3], state1[2])) & self.md4.mask 
            words2[5] = (self._rotate_right(state2[5], 7) - state2[1] - F(state2[4], state2[3], state2[2])) & self.md4.mask 
            if words1[5] != words2[5]:
                continue
            
            words1[6] = (self._rotate_right(state1[6], 11) - state1[2] - F(state1[5], state1[4], state1[3])) & self.md4.mask 
            words2[6] = (self._rotate_right(state2[6], 11) - state2[2] - F(state2[5], state2[4], state2[3])) & self.md4.mask 
            if words1[6] != words2[6]:
                continue
            
            words1[7] = (self._rotate_right(state1[7], 19) - state1[3] - F(state1[6], state1[5], state1[4])) & self.md4.mask 
            words2[7] = (self._rotate_right(state2[7], 19) - state2[3] - F(state2[6], state2[5], state2[4])) & self.md4.mask 
            if words1[7] != words2[7]:
                continue
            
            words1[8] = (self._rotate_right(state1[8], 3) - state1[4] - F(state1[7], state1[6], state1[5])) & self.md4.mask 
            words2[8] = (self._rotate_right(state2[8], 3) - state2[4] - F(state2[7], state2[6], state2[5])) & self.md4.mask 
            if words1[8] != words2[8]:
                continue 
            
            break

        if k == self.MULTISTEP_ITERATIONS-1:
            return False        
        
        for k in range(self.MULTISTEP_ITERATIONS):
            # c5,26 = d5,26, c5,27 = d5,27, c5,29 = d5,29, c5,30 = d5,30,
            # c5,32 = d5,32
            state1[18] = self._set_bits(self._rand_word(), {26: self._get_bit(state1[17], 26),
                                                            27: self._get_bit(state1[17], 27),
                                                            29: self._get_bit(state1[17], 29),
                                                            30: self._get_bit(state1[17], 30),
                                                            32: self._get_bit(state1[17], 32)})
            state2[18] = state1[18]
            
            words1[8] = (self._rotate_right(state1[18], 9) - G(state1[17], state1[16], state1[15]) - state1[14] - z) & self.md4.mask
            words2[8] = (self._rotate_right(state2[18], 9) - G(state2[17], state2[16], state2[15]) - state2[14] - z) & self.md4.mask
            if words2[8] != words1[8]:
                continue
            
            # Restore conditions from first round.
            state1[8] = self.md4._rotate_left(F(state1[7], state1[6], state1[5]) + state1[4] + words1[8] & self.md4.mask,  3)
            if self._get_bits(state1[8], [13, 14, 15, 22, 17, 19, 20, 21, 23, 26]) !=\
                                         [1, 1, 1, 1, 0, 0, 0, 0] + self._get_bits(state1[7], [23, 26]):
                continue
            state2[8] = (state1[8] + (1 << 16)) & self.md4.mask
            
            words1[9] = (self._rotate_right(state1[9], 7) - state1[5] - F(state1[8], state1[7], state1[6])) & self.md4.mask 
            words2[9] = (self._rotate_right(state2[9], 7) - state2[5] - F(state2[8], state2[7], state2[6])) & self.md4.mask 
            if words1[9] != words2[9]:
                continue
            
            words1[10] = (self._rotate_right(state1[10], 11) - state1[6] - F(state1[9], state1[8], state1[7])) & self.md4.mask 
            words2[10] = (self._rotate_right(state2[10], 11) - state2[6] - F(state2[9], state2[8], state2[7])) & self.md4.mask 
            if words1[10] != words2[10]:
                continue
            
            words1[11] = (self._rotate_right(state1[11], 19) - state1[7] - F(state1[10], state1[9], state1[8])) & self.md4.mask 
            words2[11] = (self._rotate_right(state2[11], 19) - state2[7] - F(state2[10], state2[9], state2[8])) & self.md4.mask 
            if words1[11] != words2[11]:
                continue
            
            words1[12] = (self._rotate_right(state1[12], 3) - state1[8] - F(state1[11], state1[10], state1[9])) & self.md4.mask 
            words2[12] = (self._rotate_right(state2[12], 3) - state2[8] - F(state2[11], state2[10], state2[9])) & self.md4.mask 
            if words2[12] - words1[12] != -(1 << 16):
                continue
            
            break

        if k == self.MULTISTEP_ITERATIONS-1:
            return False        

        # TODO: removed next multistep modification (b5) since it is not working.
        return True
    
    def _singlestep_modifications(self, words1, words2, state1, state2):
        a, b, c, d = self.md4.initial_state()
        F = self.md4.F
        
        # a 1,7 = b 0,7
        state1[0] = self._set_bits(self._rand_word(), {7: self._get_bit(b, 7)})
        state2[0] = state1[0]
        words1[0] = (self._rotate_right(state1[0], 3) - a - F(b, c, d)) & self.md4.mask  
        words2[0] = words1[0]
        
        # d 1,7 = 0; d 1,8 = a 1,8; d 1,11 = a 1,11
        state1[1] = self._set_bits(self._rand_word(), {7: 0,
                                                       8: self._get_bit(state1[0], 8),
                                                       11: self._get_bit(state1[0], 11)})
        state2[1] = (state1[1] + (1 << 6)) & self.md4.mask
        words1[1] = (self._rotate_right(state1[1], 7) - d - F(state1[0], b, c)) & self.md4.mask 
        words2[1] = (self._rotate_right(state2[1], 7) - d - F(state2[0], b, c)) & self.md4.mask 
        if words2[1] - words1[1] != (1 << 31):
            return False
        
        # c 1,7 = 1, c 1,8 = 1, c 1,11 = 0, c 1,26 = d 1,26
        state1[2] = self._set_bits(self._rand_word(), {7: 1, 8: 1, 11: 0,
                                                       26: self._get_bit(state1[1], 26)})            
        state2[2] = (state1[2] - (1 << 7) + (1 << 10)) & self.md4.mask
        words1[2] = (self._rotate_right(state1[2], 11) - c - F(state1[1], state1[0], b)) & self.md4.mask 
        words2[2] = (self._rotate_right(state2[2], 11) - c - F(state2[1], state2[0], b)) & self.md4.mask 
        if words2[2] - words1[2] != -(1 << 28) + (1 << 31):
            return False
        
        # b 1,7 = 1, b 1,8 = 0, b 1,11 = 0, b 1,26 = 0
        state1[3] = self._set_bits(self._rand_word(), {7: 1, 8: 0, 11: 0, 26: 0})
        state2[3] = (state1[3] + (1 << 25)) & self.md4.mask
        words1[3] = (self._rotate_right(state1[3], 19) - b - F(state1[2], state1[1], state1[0])) & self.md4.mask 
        words2[3] = (self._rotate_right(state2[3], 19) - b - F(state2[2], state2[1], state2[0])) & self.md4.mask 
        if words1[3] != words2[3]:
            return False
        
        # a 2,8 = 1, a 2,11 = 1, a 2,26 = 0, a 2,14 = b 1,14
        state1[4] = self._set_bits(self._rand_word(), {8: 1, 11: 1, 26: 0,
                                                       14: self._get_bit(state1[3], 14)})
        state2[4] = state1[4]
        words1[4] = (self._rotate_right(state1[4], 3) - state1[0] - F(state1[3], state1[2], state1[1])) & self.md4.mask 
        words2[4] = (self._rotate_right(state2[4], 3) - state2[0] - F(state2[3], state2[2], state2[1])) & self.md4.mask 
        if words1[4] != words2[4]:
            return False
    
        # d 2,14 = 0, d 2,19 = a 2,19 , d 2,20 = a 2,20 ,
        # d 2,21 = a 2,21 , d 2,22 = a 2,22 , d 2,26 = 1
        state1[5] = self._set_bits(self._rand_word(), {14: 0, 26: 1,
                                                       19: self._get_bit(state1[4], 19),
                                                       20: self._get_bit(state1[4], 20),
                                                       21: self._get_bit(state1[4], 21),
                                                       22: self._get_bit(state1[4], 22)})
        state2[5] = (state1[5] + (1 << 13)) & self.md4.mask
        words1[5] = (self._rotate_right(state1[5], 7) - state1[1] - F(state1[4], state1[3], state1[2])) & self.md4.mask 
        words2[5] = (self._rotate_right(state2[5], 7) - state2[1] - F(state2[4], state2[3], state2[2])) & self.md4.mask 
        if words1[5] != words2[5]:
            return False
    
        # c 2,13 = d 2,13 , c 2,14 = 0, c 2,15 = d 2,15 ,
        # c 2,19 = 0, c 2,20 = 0, c 2,21 = 1, c 2,22 = 0
        state1[6] = self._set_bits(self._rand_word(), {14: 0, 19: 0, 20: 0, 21: 1, 22: 0,
                                                       13: self._get_bit(state1[5], 13),
                                                       15: self._get_bit(state1[5], 15)})
        state2[6] = (state1[6] - (1 << 18) + (1 << 21)) & self.md4.mask
        words1[6] = (self._rotate_right(state1[6], 11) - state1[2] - F(state1[5], state1[4], state1[3])) & self.md4.mask 
        words2[6] = (self._rotate_right(state2[6], 11) - state2[2] - F(state2[5], state2[4], state2[3])) & self.md4.mask 
        if words1[6] != words2[6]:
            return False
    
        # b 2,13 = 1, b 2,14 = 1, b 2,15 = 0, b 2,17 = c 2,17 ,
        # b 2,19 = 0, b 2,20 = 0, b 2,21 = 0, b 2,22 = 0
        state1[7] = self._set_bits(self._rand_word(), {13: 1, 14: 1, 15: 0, 19: 0, 20: 0, 21: 0, 22: 0,
                                                       17: self._get_bit(state1[6], 17)})
        state2[7] = (state1[7] + (1 << 12)) & self.md4.mask
        words1[7] = (self._rotate_right(state1[7], 19) - state1[3] - F(state1[6], state1[5], state1[4])) & self.md4.mask 
        words2[7] = (self._rotate_right(state2[7], 19) - state2[3] - F(state2[6], state2[5], state2[4])) & self.md4.mask 
        if words1[7] != words2[7]:
            return False
        
        # a 3,13 = 1, a 3,14 = 1, a 3,15 = 1, a 3,17 = 0,
        # a 3,19 = 0, a 3,20 = 0, a 3,21 = 0, a 3,23 = b 2,23,
        # a 3,22 = 1, a 3,26 = b 2,26
        state1[8] = self._set_bits(self._rand_word(), {13: 1, 14: 1, 15: 1, 17: 0, 19: 0, 20: 0, 21: 0, 22: 1, 
                                                       23: self._get_bit(state1[7], 23),
                                                       26: self._get_bit(state1[7], 26)})
        state2[8] = (state1[8] + (1 << 16)) & self.md4.mask
        words1[8] = (self._rotate_right(state1[8], 3) - state1[4] - F(state1[7], state1[6], state1[5])) & self.md4.mask 
        words2[8] = (self._rotate_right(state2[8], 3) - state2[4] - F(state2[7], state2[6], state2[5])) & self.md4.mask 
        if words1[8] != words2[8]:
            return False        
    
        # d 3,13 = 1, d 3,14 = 1, d 3,15 = 1, d 3,17 = 0,
        # d 3,20 = 0, d 3,21 = 1, d 3,22 = 1, d 3,23 = 0,
        # d 3,26 = 1, d 3,30 = a 3,30
        state1[9] = self._set_bits(self._rand_word(), {13: 1, 14: 1, 15: 1, 17: 0, 20: 0, 21: 1, 22: 1,
                                                       23: 0, 26: 1, 
                                                       30: self._get_bit(state1[8], 30)})
        state2[9] = (state1[9] + (1 << 19) + (1 << 20) - (1 << 25)) & self.md4.mask
        words1[9] = (self._rotate_right(state1[9], 7) - state1[5] - F(state1[8], state1[7], state1[6])) & self.md4.mask 
        words2[9] = (self._rotate_right(state2[9], 7) - state2[5] - F(state2[8], state2[7], state2[6])) & self.md4.mask 
        if words1[9] != words2[9]:
            return False
    
        # c 3,17 = 1, c 3,20 = 0, c 3,21 = 0, c 3,22 = 0,
        # c 3,23 = 0, c 3,26 = 0, c 3,30 = 1, c 3,32 = d 3,32
        state1[10] = self._set_bits(self._rand_word(), {17: 1, 20: 0, 21: 0, 22: 0, 23: 0, 26: 0, 30: 1,
                                                        32: self._get_bit(state1[9], 32)})
        state2[10] = (state1[10] - (1 << 29)) & self.md4.mask
        words1[10] = (self._rotate_right(state1[10], 11) - state1[6] - F(state1[9], state1[8], state1[7])) & self.md4.mask 
        words2[10] = (self._rotate_right(state2[10], 11) - state2[6] - F(state2[9], state2[8], state2[7])) & self.md4.mask 
        if words1[10] != words2[10]:
            return False
    
        # b 3,20 = 0, b 3,21 = 1, b 3,22 = 1, b 3,23 = c 3,23,
        # b 3,26 = 1, b 3,30 = 0, b 3,32 = 0
        state1[11] = self._set_bits(self._rand_word(), {20: 0, 21: 1, 22: 1, 26: 1, 30: 0, 32: 0,
                                                        23: self._get_bit(state1[10], 23)})
        state2[11] = (state1[11] + (1 << 31)) & self.md4.mask
        words1[11] = (self._rotate_right(state1[11], 19) - state1[7] - F(state1[10], state1[9], state1[8])) & self.md4.mask 
        words2[11] = (self._rotate_right(state2[11], 19) - state2[7] - F(state2[10], state2[9], state2[8])) & self.md4.mask 
        if words1[11] != words2[11]:
            return False
        
        # a 4,23 = 0, a 4,26 = 0, a 4,27 = b 3,27 , a 4,29 = b 3,29 ,
        # a 4,30 = 1, a 4,32 = 0
        state1[12] = self._set_bits(self._rand_word(), {23: 0, 26: 0, 30: 1, 32: 0,
                                                        27: self._get_bit(state1[11], 27),
                                                        29: self._get_bit(state1[11], 29)})
        state2[12] = (state1[12] + (1 << 22) + (1 << 25)) & self.md4.mask
        words1[12] = (self._rotate_right(state1[12], 3) - state1[8] - F(state1[11], state1[10], state1[9])) & self.md4.mask 
        words2[12] = (self._rotate_right(state2[12], 3) - state2[8] - F(state2[11], state2[10], state2[9])) & self.md4.mask 
        if words2[12] - words1[12] != -(1 << 16):
            return False
        
        # d 4,23 = 0, d 4,26 = 0, d 4,27 = 1, d 4,29 = 1,
        # d 4,30 = 0, d 4,32 = 1
        state1[13] = self._set_bits(self._rand_word(), {23: 0, 26: 0, 27: 1, 29: 1, 30: 0, 32: 1})
        state2[13] = (state1[13] - (1 << 26) + (1 << 28)) & self.md4.mask
        words1[13] = (self._rotate_right(state1[13], 7) - state1[9] - F(state1[12], state1[11], state1[10])) & self.md4.mask 
        words2[13] = (self._rotate_right(state2[13], 7) - state2[9] - F(state2[12], state2[11], state2[10])) & self.md4.mask 
        if words1[13] != words2[13]:
            return False
        
        # c 4,19 = d 4,19 , c 4,23 = 1, c 4,26 = 1, c 4,27 = 0,
        # c 4,29 = 0, c 4,30 = 0
        state1[14] = self._set_bits(self._rand_word(), {23: 1, 26: 1, 27: 0, 29: 0, 30: 0,
                                                        19: self._get_bit(state1[13], 19)})
        state2[14] = state1[14]
        words1[14] = (self._rotate_right(state1[14], 11) - state1[10] - F(state1[13], state1[12], state1[11])) & self.md4.mask 
        words2[14] = (self._rotate_right(state2[14], 11) - state2[10] - F(state2[13], state2[12], state2[11])) & self.md4.mask 
        if words1[14] != words2[14]:
            return False
        
        # b 4,19 = 0, b 4,26 = c 4,26 = 1, b 4,27 = 1, b 4,29 = 1, b 4,30 = 0
        state1[15] = self._set_bits(self._rand_word(), {19: 0, 26: 1, 27: 1, 29: 1, 30: 0})
        state2[15] = (state1[15] + (1 << 18)) & self.md4.mask
        words1[15] = (self._rotate_right(state1[15], 19) - state1[11] - F(state1[14], state1[13], state1[12])) & self.md4.mask 
        words2[15] = (self._rotate_right(state2[15], 19) - state2[11] - F(state2[14], state2[13], state2[12])) & self.md4.mask 
        if words1[15] != words2[15]:
            return False
        
        return True
    
    def _verify_remaining_steps(self, words1, words2, state1, state2):
        _all_steps_valid = True
        
        for j in range(19, 48):
            func, const = (self.md4.G, 0x5a827999) if j < 32 else (self.md4.H, 0x6ed9eba1)
            if j in [21, 25, 29]:
                s = 5
            elif j in [19, 23, 27, 31]:
                s = 13
            elif j in [34, 38, 42, 46]:
                s = 11
            elif j in [35, 39, 43, 47]:
                s = 15                    
            elif j in [22, 26, 30, 33, 37, 41, 45]:
                s = 9
            else:
                s = 3
            i = {19: 12, 20: 1, 21: 5, 22: 9, 23: 13, 24: 2, 25: 6, 
                 26: 10, 27: 14, 28: 3, 29: 7, 30: 11, 31: 15, 32: 0, 33: 8, 34: 4, 35: 12, 
                 36: 2, 37: 10, 38: 6, 39: 14, 40: 1, 41: 9, 42: 5, 43: 13, 44: 3, 45: 11,
                 46: 7, 47: 15}[j]
            state1[j] = self.md4._rotate_left((state1[j-4] + func(state1[j-1], state1[j-2], state1[j-3]) + words1[i] + const) & self.md4.mask, s) 
            state2[j] = self.md4._rotate_left((state2[j-4] + func(state2[j-1], state2[j-2], state2[j-3]) + words2[i] + const) & self.md4.mask, s)             
            if j == 19 and state2[j] != ((state1[j] - (1 << 29) + (1 << 31)) & 0xffffffff):
                _all_steps_valid = False
                break
            elif j == 20 and state2[j] != ((state1[j] + (1 << 28) - (1 << 31)) & 0xffffffff):
                _all_steps_valid = False
                break  
            elif (j == 35 or j == 36) and state2[j] != ((state1[j] + (1 << 31)) & 0xffffffff):
                _all_steps_valid = False
                break
            elif j not in [19, 20, 35, 36] and state1[j] != state2[j]:
                _all_steps_valid = False
                break
        
        return _all_steps_valid
        
    def value(self):
        words1 = [0 for _ in range(16)]
        words2 = [0 for _ in range(16)]
        state1 = [0 for _ in range(48)]
        state2 = [0 for _ in range(48)]
        
        while True:
            if not self._singlestep_modifications(words1, words2, state1, state2):
                continue

            if not self._multistep_modifications(words1, words2, state1, state2):
                continue
            
            if self._verify_remaining_steps(words1, words2, state1, state2):
                break
            
        return self._build_message_from(words1),\
               self._build_message_from(words2)