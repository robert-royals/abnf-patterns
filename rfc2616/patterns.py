from generic import ConstantLength


class Octet(ConstantLength):
    # OCTET          = <any 8-bit sequence of data>
    length = 1

    @classmethod
    def match_length_correct(self, val: bytes) -> bool:
        return True


class UpAlpha(ConstantLength):
    # UPALPHA        = <any US-ASCII uppercase letter "A".."Z">
    length = 1

    @classmethod
    def match_length_correct(self, val: bytes) -> bool:
        return b"A" <= val <= b"Z"


class LoAlpha(ConstantLength):
    # LOALPHA        = <any US-ASCII lowercase letter "a".."z">
    length = 1

    @classmethod
    def match_length_correct(self, val: bytes) -> bool:
        return b"a" <= val <= b"z"


class Alpha(ConstantLength):
    # ALPHA          = UPALPHA | LOALPHA
    length = 1

    @classmethod
    def match_length_correct(self, val: bytes) -> bool:
        return (
            UpAlpha.match_length_correct(val)
            or LoAlpha.match_length_correct(val)
        )


class Digit(ConstantLength):
    # DIGIT          = <any US-ASCII digit "0".."9">
    length = 1

    @classmethod
    def match_length_correct(self, val: bytes) -> bool:
        return b"0" <= val <= b"9"
