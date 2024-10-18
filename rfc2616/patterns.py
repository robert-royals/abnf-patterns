def octet(val: bytes) -> bool:
    # OCTET          = <any 8-bit sequence of data>
    return len(val) == 1


def upalpha(val: bytes) -> bool:
    # UPALPHA        = <any US-ASCII uppercase letter "A".."Z">
    return len(val) == 1 and (b"A" <= val <= b"Z")


def loalpha(val: bytes) -> bool:
    # LOALPHA        = <any US-ASCII lowercase letter "a".."z">
    return len(val) == 1 and (b"a" <= val <= b"z")


def alpha(val: bytes) -> bool:
    # ALPHA          = UPALPHA | LOALPHA
    return upalpha(val) or loalpha(val)
