class NthRoot(object):

    def __init__(self, n):
        if n <= 0:
            raise RuntimeError('n should be positive')
        self.n = n

    def value(self, x):
        # Compute y s.t. y**self.n == [nth_root(x, self.n)]
        # [.] denotes the floor function.

        if x == 0:
            return 0
        
        # Find y in a binary search fashion.
        upper_limit = lower_limit = y = 1
        while upper_limit ** self.n < x:
            lower_limit = upper_limit
            upper_limit <<= 1
        while lower_limit < upper_limit:
            mid = (lower_limit+upper_limit)/2
            mid_value = mid**self.n
            if lower_limit < mid and mid_value < x:
                lower_limit = mid
            elif upper_limit > mid and mid_value > x:
                upper_limit = mid
            else:
                y = mid
                break
            
        return y