def upalpha(val: bytes) -> bool:
    # UPALPHA        = <any US-ASCII uppercase letter "A".."Z">
    return len(val) == 1 and (b"A" <= val <= b"Z")
