from rfc2234.patterns import Alpha, Digit
from generic import (
    ConstantLength,
    DefaultMatchAll,
    MatchResult,
    literal_compare,
)


class Base64Char(ConstantLength):
    length = 1

    @classmethod
    def match_length_correct(cls, val: bytes) -> bool:
        return (
            Alpha.match_full(val)
            or Digit.match_full(val)
            or literal_compare(b"+").match_full(val)
            or literal_compare(b"/").match_full(val)
        )


class Base64Data(ConstantLength):
    length = 4

    @classmethod
    def match_length_correct(cls, val: bytes) -> bool:
        return all(Base64Char.match_from(val, i) for i in range(cls.length))


class Base64Padding(ConstantLength):
    length = 4

    padding_matcher = literal_compare(b"=")

    @classmethod
    def match_length_correct(cls, val: bytes) -> bool:
        return cls.match_n_padding(val, 1) or cls.match_n_padding(val, 2)

    @classmethod
    def match_n_padding(cls, val: bytes, n: int) -> bool:
        data_part = all(
            Base64Char.match_from(val, i)
            for i in range(cls.length - n)
        )
        padding_part = all(
            cls.padding_matcher.match_from(val, i)
            for i in range(cls.length - n, cls.length)
        )
        return data_part and padding_part


class Base64ValueNonEmpty(DefaultMatchAll):
    """
        base64-value-non-empty = (1*base64-data [ base64-padding ]) |
                                 base64-padding
    """
    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        matched_length = 0
        while 1:
            data_result = Base64Data.match_from(val, matched_length)
            if data_result is not None:
                matched_length += data_result.length
            else:
                break
        padding_result = Base64Padding.match_from(val, matched_length)
        if matched_length == 0:
            # Only a match if the padding was found
            return padding_result
        else:
            # Already have a match. Extend match if there is also padding.
            if padding_result is not None:
                matched_length += padding_result.length
            return MatchResult(start=0, length=matched_length)


class SecWebSocketAccept(Base64ValueNonEmpty):
    ...
