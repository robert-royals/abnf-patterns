def upalpha(val: bytes) -> bool:
    return len(val) == 1 and ("A" <= val <= "Z")
