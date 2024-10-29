from generic import DefaultMatchAll, MatchResult, literal_compare

from rfc2234.patterns import Digit, HexDig


class H16(DefaultMatchAll):
    """
        h16         = 1*4HEXDIG
    """
    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        matches = 0
        for n in range(4):
            if HexDig.match_from(val, n) is None:
                break
            else:
                matches += 1

        if matches == 0:
            return None
        else:
            return MatchResult(start=0, length=matches)


class DecOctet(DefaultMatchAll):
    """
        String digit 0 to 255
        dec-octet   = DIGIT                 ; 0-9
                  / %x31-39 DIGIT         ; 10-99
                  / "1" 2DIGIT            ; 100-199
                  / "2" %x30-34 DIGIT     ; 200-249
                  / "25" %x30-35          ; 250-255
    """

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        # A bit messy, but we follow the rules faithfully.

        dig_1_match = Digit.match_from(val, 0)
        dig_2_match = Digit.match_from(val, 1)
        dig_3_match = Digit.match_from(val, 2)

        no_match = None
        match_1 = MatchResult(start=0, length=1)
        match_2 = MatchResult(start=0, length=2)
        match_3 = MatchResult(start=0, length=3)

        if dig_1_match is None:
            # The first value is not a digit: no match
            return no_match

        if Digit.byte_equals_digit(val[0], 0):
            # The first value is a 'zero', this is all it can match, as things
            # like '01' aren't defined to match the ABNF.
            return dig_1_match
        elif Digit.byte_equals_digit(val[0], 1):
            # The first value is a 1, see how many more digits follow it, there
            # is no restriction here up to length three as all values 100-199
            # are acceptable.
            if dig_2_match is None:
                return match_1
            elif dig_3_match is None:
                return match_2
            else:
                return match_3
        elif Digit.byte_equals_digit(val[0], 2):
            # First digit is a 2, some special cases here:
            if dig_2_match is None:
                # Not followed by another digit, return the first value.
                return match_1
            elif Digit.byte_in_range(val[1], 0, 4):
                # Followed by 0-4, see if any other digit follows, all values
                # 200 to 249 are acceptable.
                if dig_3_match is None:
                    return match_2
                else:
                    return match_3
            elif Digit.byte_equals_digit(val[1], 5):
                # Followed by a 5, either followed by no digit, or 0-5.
                if dig_3_match is None:
                    return match_2
                elif Digit.byte_in_range(val[2], 0, 5):
                    # The values 250-255
                    return match_3
                else:
                    # If it's followed by 6 or more, just match the first two
                    # digits only. eg 259 will match 25 and then stop looking
                    # further. Note: 259 would match: (2 dec-octet), although
                    # ambiguously.
                    return match_2
            else:
                # Followed by 6 or more, so just match the two digits, as
                # values 260-299 are too high.
                return match_2
        else:
            # First digit is 3 or more, can only add at most one more digit,
            # which can be anything, since #30-99 are all valid, but a third
            # digit would make them too large.
            if dig_2_match is not None:
                return match_2
            else:
                return match_1


class IPv4Address(DefaultMatchAll):
    """
        dec-octet "." dec-octet "." dec-octet "." dec-octet
    """
    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        matched_length = 0
        dot_matcher = literal_compare(b".")
        for i in range(4):
            dec_octet_match = DecOctet.match_from(val, matched_length)
            if dec_octet_match is None:
                return None
            else:
                matched_length += dec_octet_match.length

            if i == 3:
                return MatchResult(start=0, length=matched_length)

            dot_match = dot_matcher.match_from(val, matched_length)
            if dot_match is None:
                return None
            else:
                matched_length += dot_match.length
        return None


class LS32(DefaultMatchAll):
    """
        ls32        = ( h16 ":" h16 ) / IPv4address
    """
    colon_matcher = literal_compare(b":")

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        return cls.h16_pair_match(val) or cls.ipv4_match(val)

    @classmethod
    def h16_pair_match(cls, val: bytes) -> MatchResult | None:
        h16_match = H16.match_start(val)
        if h16_match is None:
            return None

        matched_length = h16_match.length
        colon_match = cls.colon_matcher.match_from(val, matched_length)
        if colon_match is None:
            return None

        matched_length += colon_match.length

        h16_match = H16.match_from(val, matched_length)
        if h16_match is None:
            return None
        else:
            matched_length += h16_match.length
            return MatchResult(start=0, length=matched_length)

    @classmethod
    def ipv4_match(cls, val: bytes) -> MatchResult | None:
        return IPv4Address.match_start(val)


class IPv6Address(DefaultMatchAll):
    """
        IPv6address =                            6( h16 ":" ) ls32
                    /                       "::" 5( h16 ":" ) ls32
                    / [               h16 ] "::" 4( h16 ":" ) ls32
                    / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                    / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                    / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                    / [ *4( h16 ":" ) h16 ] "::"              ls32
                    / [ *5( h16 ":" ) h16 ] "::"              h16
                    / [ *6( h16 ":" ) h16 ] "::"
        This can be expressed equivalently as:
        IPv6address =                  "::" [ h16 / *5( h16 ":" ) ls32 ]
                    /              h16 "::" [ h16 / *4( h16 ":" ) ls32 ]
                    / 1( h16 ":" ) h16 "::" [ h16 / *3( h16 ":" ) ls32 ]
                    / 2( h16 ":" ) h16 "::" [ h16 / *2( h16 ":" ) ls32 ]
                    / 3( h16 ":" ) h16 "::" [ h16 / *1( h16 ":" ) ls32 ]
                    / 4( h16 ":" ) h16 "::" [ h16 / ls32 ]
                    / 5( h16 ":" ) h16 "::" [ h16 ]
                    / 6( h16 ":" ) ( h16 "::" / ls32 )
        which is how we will handle it to aid left-to-right processing.

    """

    colon_matcher = literal_compare(b":").match_from

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        # First see how many repeats of
        #     ( h16 ":" )
        # we can find, up to a maximum of 6.
        h16s_matched = 0
        offset = 0

        while h16s_matched < 6:
            h16_match_result = H16.match_from(val, offset)
            if h16_match_result is None:
                break
            colon_match_result = cls.colon_matcher(val, h16_match_result.end)
            if colon_match_result is None:
                # No match! For the first 6, each h16 MUST be followed by a ":"
                return None
            offset = colon_match_result.end
            h16s_matched += 1

        colon_match_result = cls.colon_matcher(val, offset)

        if h16s_matched == 6 and colon_match_result is None:
            # We deal with the cases:
            #     6( h16 ":" ) ( h16 "::" / ls32 )
            h16_match_result = H16.match_from(val, offset)
            if not h16_match_result:
                return None
            ls32_match_result = LS32.match_from(val, offset)
            if ls32_match_result:
                return MatchResult(start=0, length=ls32_match_result.end)
            # Otherwise it must end with (h16 "::")
            offset = h16_match_result.end
            for _ in range(2):
                colon_match_result = cls.colon_matcher(val, offset)
                if not colon_match_result:
                    return None
                offset += colon_match_result.length
            return MatchResult(start=0, length=offset)

        if colon_match_result is None:
            # All remaining cases must have "::" at this point, if no colon
            # we return None
            return None

        # If it is the cases of
        #     "::" [ h16 / *5( h16 ":" ) ls32 ]
        # we need an extra colon. In the other cases the pattern ( h16 ":" )
        # matched the first of the "::" already
        if h16s_matched == 0:
            colon_match_result = cls.colon_matcher(val, colon_match_result.end)
            if not colon_match_result:
                # Unexpected number of colons. No matching address possible.
                return None

        # Next deal with the post "::" part. The amount of ( h16 ":" )
        # repetitions we can have depends on how many h16s were matched
        # previously.
        # Anything more proceeding must begin 'h16' as even an ls32 will begin
        # in a manner matching h16. So if h16 does not follow, we know we can
        # just treat it as ending at the "::"
        h16_match_result = H16.match_from(val, colon_match_result.end)
        if not h16_match_result:
            return MatchResult(start=0, length=colon_match_result.end)
        h16_end = h16_match_result.end

        for i in range(6 - h16s_matched):
            # After the last colon, we know there is a h16 matching. Does an
            # ls32 pattern also follow the colon?
            ls32_match_result = LS32.match_from(val, colon_match_result.end)
            if not ls32_match_result:
                # If not, then the :h16 must have been the end of the address.
                return MatchResult(start=0, length=h16_end)
            # Did a colon follow the h16?
            colon_match_result = cls.colon_matcher(val, h16_end)
            ls32_end = ls32_match_result.end
            if not colon_match_result:
                # If a colon didn't follow the h16, then the ls32 must have
                # been in the ipv4 format, and this is the end of the address.
                return MatchResult(start=0, length=ls32_end)
            # If a colon does follow the h16, then the ls32 must have been in
            # the (h16 : h16) form, so the ls32 also ends where a h16 ends
            h16_end = ls32_end

        return MatchResult(start=0, length=h16_end)
