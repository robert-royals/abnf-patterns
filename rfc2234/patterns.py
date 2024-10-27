from generic import ConstantLength

from rfc2616.patterns import LoAlpha, UpAlpha


class Digit(ConstantLength):
    # DIGIT          = <any US-ASCII digit "0".."9">
    length = 1
    zero_val = b"0"[0]

    @classmethod
    def match_length_correct(cls, val: bytes) -> bool:
        return cls.digit_char(0) <= val[0] <= cls.digit_char(9)

    @classmethod
    def digit_char(cls, n: int) -> int:
        if 0 <= n <= 9:
            return n + cls.zero_val
        else:
            raise ValueError

    @classmethod
    def byte_equals_digit(cls, val: int, n: int) -> bool:
        return val == cls.digit_char(n)

    @classmethod
    def byte_in_range(cls, val: int, n1: int, n2: int) -> bool:
        return cls.digit_char(n1) <= val <= cls.digit_char(n2)


class Alpha(ConstantLength):
    # ALPHA          = UPALPHA | LOALPHA
    length = 1

    @classmethod
    def match_length_correct(self, val: bytes) -> bool:
        return (
            UpAlpha.match_length_correct(val)
            or LoAlpha.match_length_correct(val)
        )


class HexDig(ConstantLength):
    """
        HEXDIG         =  DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
        Note: ABNF is case insensitive so "a"-"f" too.
    """
    length = 1

    @classmethod
    def match_length_correct(self, val: bytes) -> bool:
        if Digit.match_length_correct(val):
            return True
        else:
            return (b"A" <= val <= b"F") or (b"a" <= val <= b"f")
