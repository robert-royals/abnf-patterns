class MatchResult:
    def __init__(self, start: int, length: int):
        self.start = start
        self.length = length

    @property
    def end(self) -> int:
        return self.start + self.length


class Matcher:
    @classmethod
    def match_full(cls, val: bytes) -> bool:
        """
        Check the full byte string matches this pattern with no remaining bytes
        """
        raise NotImplementedError

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        return cls.match_from(val, 0)

    @classmethod
    def match_from(cls, val: bytes, start: int) -> MatchResult | None:
        """
        Check starting at position 'from' that the pattern matches
        """
        raise NotImplementedError


class ConstantLength(Matcher):
    length: int

    @classmethod
    def match_length_correct(cls, val: bytes) -> bool:
        """Handles the case where we know the string is the correct length"""
        raise NotImplementedError

    @classmethod
    def match_full(cls, val: bytes) -> bool:
        if len(val) != cls.length:
            return False
        else:
            return cls.match_length_correct(val)

    @classmethod
    def match_from(cls, val: bytes, start: int) -> MatchResult | None:
        if (
            len(val) >= start + cls.length
        ) and (
            cls.match_length_correct(val[start: start + cls.length])
        ):
            return MatchResult(start, cls.length)
        else:
            return None


class LiteralCompare(ConstantLength):
    str_to_match: bytes

    @classmethod
    def match_length_correct(cls, val: bytes) -> bool:
        """Check val is the same as the (sub)class's string"""
        return val == cls.str_to_match


def literal_compare(str_to_match: str) -> type[LiteralCompare]:
    # Takes a string such as '+' and creates a Matcher class for it
    name = f"LiteralCompare<{str_to_match}>"
    attrs = {
        "str_to_match": str_to_match.encode(),
        "length": len(str_to_match)
    }
    return type(name, (LiteralCompare,), attrs)


class DefaultMatchAll(Matcher):
    """
    Implement a match_from, and defines the match_full from that.

    If the 'match_start' then matches the whole string, the match_full passes
    """

    @classmethod
    def match_full(cls, val: bytes) -> bool:
        match_result = cls.match_start(val)
        return (match_result is not None and match_result.length == len(val))
