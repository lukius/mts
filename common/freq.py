from collections import defaultdict


class FrequencyScorer(object):
    
    POINTS_ON_MATCH = 1
    EQUALITY_TOLERANCE = 0.01    
    
    def __init__(self, text):
        self.text = text
        self.frequencies = self._init_frequencies()
    
    def _init_frequencies(self):
        raise NotImplementedError
    
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
    
    def value(self):
        sampled_frequencies = self._compute_frequencies()
        score = 0
        for (char, frequency) in self.frequencies.items():
            sampled_frequency = sampled_frequencies[char]
            if self._equals_with_tolerance(self.EQUALITY_TOLERANCE, frequency,
                                           sampled_frequency):
                score += self.POINTS_ON_MATCH
        return score


class EnglishFrequencyScorer(FrequencyScorer):
    
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