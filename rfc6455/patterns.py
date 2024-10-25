from rfc2616.patterns import Alpha, Digit
from generic import literal_compare


def base64_character(val: bytes) -> bool:
    return (
        Alpha.match_full(val)
        or Digit.match_full(val)
        or literal_compare("+").match_full(val)
        or literal_compare("/").match_full(val)
    )
