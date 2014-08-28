from __future__ import absolute_import

import random


class Concatenation(object):
    
    def __init__(self, objs):
        self.objs = objs
        
    def value(self):
        initial_value = type(self.objs[0])()
        return reduce(lambda result, obj: result + obj,
                      self.objs, initial_value)
        
        
class FileLines(object):
    
    def __init__(self, filename):
        self.filename = filename
        
    def value(self):
        return open(self.filename, 'r').read().splitlines()


class Average(object):
    
    def __init__(self, values):
        self.values = values
        
    def value(self):
        length = len(self.values)
        return sum(self.values)/float(length)
    

class RandomByteGenerator(object):
    
    MAX_VALUE = 500
    
    def value(self, count=None):
        if count is None:
            count = random.randint(1, self.MAX_VALUE)
        random_bytes = [chr(random.choice(range(255))) for _ in range(count)]
        return Concatenation(random_bytes).value()
    
    
class AllEqual(object):
    
    def __init__(self, objs):
        self.objs = objs
        
    def value(self, obj=None):
        if obj is None:
            value = len(set(self.objs)) == 1
        else:
            value = all(map(lambda _obj: _obj == obj, self.objs))
        return value
    

class HammingDistance(object):
    
    def __init__(self, string1, string2):
        if len(string1) != len(string2):
            raise RuntimeError('strings must have equal length')        
        self.string1 = string1
        self.string2 = string2
        
    def value(self):
        from common.converters import BytesToBinary
        bin_string1 = BytesToBinary(self.string1).value()
        bin_string2 = BytesToBinary(self.string2).value()
        pairs = zip(bin_string1, bin_string2)
        differences = reduce(lambda count, (bit1,bit2): count + (bit1 != bit2),
                             pairs, 0)
        return differences