from rfc2234.patterns import Alpha as Letter, Digit

from generic import Matcher, literal_compare, DefaultMatchAll, MatchResult
import special_chars


class LetDig(DefaultMatchAll):
    """
        <let-dig> ::= <letter> | <digit>
    """

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        return Letter.match_start(val) or Digit.match_start(val)


class LetDigHypMatchResult(MatchResult):
    matching_symbol: type[Matcher]

    def __init__(
        self, *, start: int, length: int, matching_symbol: type[Matcher]
    ):
        self.matching_symbol = matching_symbol
        super().__init__(start=start, length=length)


class LetDigHyp(DefaultMatchAll[LetDigHypMatchResult]):
    """
        <let-dig-hyp> ::= <let-dig> | "-"
    """

    hyphen_matcher = literal_compare(b"-")

    @classmethod
    def match_start(cls, val: bytes) -> LetDigHypMatchResult | None:
        let_dig_match = LetDig.match_start(val)
        if let_dig_match:
            return LetDigHypMatchResult(
                start=0, length=let_dig_match.length, matching_symbol=LetDig
            )
        hyphen_match = cls.hyphen_matcher.match_start(val)
        if hyphen_match:
            return LetDigHypMatchResult(
                start=0,
                length=hyphen_match.length,
                matching_symbol=cls.hyphen_matcher
            )

        return None


class LDHStr(DefaultMatchAll):
    """
        <let-dig-hyp> | <let-dig-hyp> <ldh-str>
    """

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        offset = 0
        while 1:
            lhd_match = LetDigHyp.match_from(val, offset)
            if not lhd_match:
                break
            else:
                offset = lhd_match.end
        if offset > 0:
            return MatchResult(start=0, length=offset)
        else:
            return None


class Label(DefaultMatchAll):
    """
        <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]
        and:
            There are also some restrictions on the length.
            Labels must be 63 characters or less.
    """
    max_label_length: int = 63

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        letter_match = Letter.match_start(val)
        if not letter_match:
            return None

        # After a proceeding <letter> this pattern requires looking ahead.
        # The 'let-dig' is also an 'ldh-str' so if we just take the largest
        # possible ldh-str, we won't have any remaining let-dig to consider.
        # Rather than consuming a whole ldh-str which is of arbitrary length,
        # we manually compute label without needing the LDHStr pattern.

        offset = letter_match.end

        last_let_dig_match = offset
        while offset < cls.max_label_length:
            ldh_match = LetDigHyp.match_from(val, offset)

            if ldh_match:
                # For mypy. Unhappy with having to do this. Tried lots of ways
                # to use generic types to get the match_from to automatically
                # return type LetDigHypeMatchResult but I can't work out how
                # to do it.
                offset = ldh_match.end
                if ldh_match.matching_symbol is LetDig:
                    last_let_dig_match = offset
            else:
                break

        return MatchResult(start=0, length=last_let_dig_match)


class SubDomain(DefaultMatchAll):
    """
        <subdomain> ::= <label> | <subdomain> "." <label>

        in other words, a "." separated sequence of at least one label.
    """

    length_limit: int | None = None

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        if cls.length_limit is not None:
            val = val[: cls.length_limit]

        label_match = Label.match_start(val)
        if not label_match:
            return None

        offset = label_match.end
        while 1:
            dot_match = literal_compare(b".").match_from(val, offset)
            if not dot_match:
                return MatchResult(start=0, length=offset)
            label_match = Label.match_from(val, dot_match.end)
            if label_match:
                offset = label_match.end
            else:
                return MatchResult(start=0, length=offset)


class Domain(SubDomain):
    length_limit = 255

    @classmethod
    def match_start(cls, val: bytes) -> MatchResult | None:
        return (
            super().match_start(val)
        ) or (
            literal_compare(special_chars.space).match_start(val)
        )
