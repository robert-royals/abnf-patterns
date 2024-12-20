from generic import (
    ConstantLength,
    DefaultMatchAll,
    MatchResult,
    LiteralCompare,
)
import special_chars


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


class CRLF(LiteralCompare):
    str_to_match = special_chars.carriage_return + special_chars.linefeed


class LWS(DefaultMatchAll):
    """
        Linear white space

        LWS            = [CRLF] 1*( SP | HT )

        An optional CRLF followed by a non-empty sequence of spaces and tabs
    """
    class WhiteSpace(ConstantLength):
        length = 1

        @classmethod
        def match_length_correct(cls, val: bytes) -> bool:
            return val in (special_chars.space, special_chars.horizontal_tab)

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        matched_length = 0
        crlf_match = CRLF.match_start(val)
        if crlf_match is not None:
            matched_length += crlf_match.length

        have_whitespace = False

        while 1:
            result = cls.WhiteSpace.match_from(val, matched_length)
            if result is not None:
                matched_length += result.length
                have_whitespace = True
            else:
                break

        if not have_whitespace:
            return None
        else:
            return MatchResult(start=0, length=matched_length)
