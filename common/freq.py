from collections import defaultdict


class FrequencyScorer(object):
    
    MAX_POINTS_ON_MATCH = 8
    MIN_PENALTY = 1
    POINTS_ON_SPACE_MATCH = 2*MAX_POINTS_ON_MATCH
    EQUALITY_TOLERANCE = 0.01
    frequencies = None
    
    def __init__(self, text):
        self.text = text
        self._init_tables()
        
    def _init_tables(self):
        if self.frequencies is None:
            self.__class__.frequencies = self._init_frequencies()
            self.__class__.score_table = self._init_score_table()
    
    def _init_frequencies(self):
        raise NotImplementedError
    
    def _init_score_table(self):
        score_table = dict()
        sorted_items = sorted(self.frequencies.items(),
                              key=lambda item: item[1], reverse=True)
        for (index, (char, _)) in enumerate(sorted_items, 1):
            penalty = self.MIN_PENALTY
            if index > 4:
                penalty *= 2
            if index > 12:
                penalty *= 2
            if index > 20:
                penalty *= 2
            points = self.MAX_POINTS_ON_MATCH / penalty
            score_table[char] = points 
        return score_table
    
    def _normalize(self, text):
        # 1. Remove uppercase
        text = text.lower()
        # 2. Keep letters only
        text = filter(lambda char: char in self.frequencies, text)
        return text
    
    def _compute_frequencies(self):
        sampled_frequencies = defaultdict(lambda: 0)
        text = self._normalize(self.text)
        length = len(text)
        if length > 0:
            for char in self.frequencies:
                occurrences = reduce(lambda count, letter: count + (letter==char),
                                     text, 0)
                sampled_frequencies[char] = occurrences / float(length)
        return sampled_frequencies
    
    def _equals_with_tolerance(self, tolerance, number1, number2):
        return number1 - tolerance <= number2 <= number1 + tolerance
    
    def _compute_points_for(self, char):
        char_points = self.score_table[char]
        extra_points = self._compute_extra_points()
        return char_points + extra_points
    
    def _compute_extra_points(self):
        extra_points = 0
        spaces = len(self.text.split(' ')) - 1
        avg_spaces = len(self.text)/self.AVERAGE_WORD_LENGTH - 1
        if self._equals_with_tolerance(1, avg_spaces, spaces):
            extra_points += self.POINTS_ON_SPACE_MATCH
        return extra_points
    
    def value(self):
        sampled_frequencies = self._compute_frequencies()
        score = 0
        for (char, frequency) in self.frequencies.items():
            sampled_frequency = sampled_frequencies[char]
            if self._equals_with_tolerance(self.EQUALITY_TOLERANCE, frequency,
                                           sampled_frequency):
                score += self._compute_points_for(char)
        return score


class EnglishFrequencyScorer(FrequencyScorer):
    
    AVERAGE_WORD_LENGTH = 5
    
    def _init_frequencies(self):
        frequencies = dict()
        frequencies['e'] = 0.130001
        frequencies['t'] = 0.09056
        frequencies['a'] = 0.08167
        frequencies['o'] = 0.07507
        frequencies['i'] = 0.06966
        frequencies['n'] = 0.06749
        frequencies['s'] = 0.06327
        frequencies['h'] = 0.06094
        frequencies['r'] = 0.05987
        frequencies['d'] = 0.04253
        frequencies['l'] = 0.04025
        frequencies['c'] = 0.02782
        frequencies['u'] = 0.02578
        frequencies['m'] = 0.02406
        frequencies['w'] = 0.0236
        frequencies['f'] = 0.0228
        frequencies['g'] = 0.02015
        frequencies['y'] = 0.01974
        frequencies['p'] = 0.01929
        frequencies['b'] = 0.01492
        frequencies['v'] = 0.00978
        frequencies['k'] = 0.00772
        frequencies['j'] = 0.00153
        frequencies['x'] = 0.0015
        frequencies['q'] = 0.00095
        frequencies['z'] = 0.00074
        return frequencies        