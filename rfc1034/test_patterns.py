from unittest import TestCase

from generic import MatchResult
from rfc1034.patterns import (
    Domain,
    Label,
    LDHStr,
    LetDig,
    LetDigHyp,
    SubDomain,
)


class TestLetDig(TestCase):
    def test_let_dig(self) -> None:
        self.assertTrue(LetDig.match_full(b'a'))
        self.assertTrue(LetDig.match_full(b'A'))
        self.assertTrue(LetDig.match_full(b'1'))

        self.assertFalse(LetDig.match_full(b'!'))
        self.assertFalse(LetDig.match_full(b' '))
        self.assertFalse(LetDig.match_full(b''))
        self.assertFalse(LetDig.match_full(b'123'))
        self.assertFalse(LetDig.match_full(b'xyz'))
        self.assertFalse(LetDig.match_full(b'-'))


class TestLetDigHype(TestCase):
    def test_let_dig_hype(self) -> None:
        self.assertTrue(LetDigHyp.match_full(b'a'))
        self.assertTrue(LetDigHyp.match_full(b'A'))
        self.assertTrue(LetDigHyp.match_full(b'1'))
        self.assertTrue(LetDigHyp.match_full(b'-'))

        self.assertFalse(LetDigHyp.match_full(b'!'))
        self.assertFalse(LetDigHyp.match_full(b' '))
        self.assertFalse(LetDigHyp.match_full(b''))
        self.assertFalse(LetDigHyp.match_full(b'123'))
        self.assertFalse(LetDigHyp.match_full(b'xyz'))


class TestLDHStr(TestCase):
    def test_lhd_str(self) -> None:
        self.assertTrue(LDHStr.match_full(b"abc---123"))
        self.assertTrue(LDHStr.match_full(b"X-Y-Z"))

        self.assertFalse(LDHStr.match_full(b""))
        self.assertFalse(LDHStr.match_full(b" "))
        self.assertFalse(LDHStr.match_full(b"_"))
        self.assertFalse(LDHStr.match_full(b"1."))

        matching_str = b"abc---123XYZ"

        match_result = LDHStr.match_start(matching_str + b"!xyz")
        self.assertIsNotNone(match_result)
        assert isinstance(match_result, MatchResult)
        self.assertEqual(match_result.length, len(matching_str))


class TestLabel(TestCase):
    def test_label(self) -> None:
        self.assertTrue(Label.match_full(b"a"))
        self.assertTrue(Label.match_full(b"aA"))
        self.assertTrue(Label.match_full(b"a-A"))
        self.assertTrue(Label.match_full(b"a-----xyz-----At"))
        self.assertTrue(Label.match_full(b"a0"))
        self.assertTrue(Label.match_full(b"a--0"))
        self.assertTrue(Label.match_full(b"a"*63))

        self.assertFalse(Label.match_full(b"a-"))
        self.assertFalse(Label.match_full(b"0"))
        self.assertFalse(Label.match_full(b"0a"))
        self.assertFalse(Label.match_full(b"a---abc-"))
        self.assertFalse(Label.match_full(b"a"*64))

        matching_str = b"a-----xyz123"
        match_result = Label.match_start(matching_str + b"----")
        self.assertIsNotNone(match_result)
        assert isinstance(match_result, MatchResult)
        self.assertEqual(match_result.length, len(matching_str))


class TestSubDomain(TestCase):
    def test_subdomain(self) -> None:
        self.assertTrue(SubDomain.match_full(b"a"))
        self.assertTrue(SubDomain.match_full(b"a-0.b---X"))
        self.assertTrue(SubDomain.match_full(b"A.ISI.EDU"))
        self.assertTrue(SubDomain.match_full(b"XX.LCS.MIT.EDU"))
        self.assertTrue(SubDomain.match_full(b"SRI-NIC.ARPA"))
        self.assertTrue(SubDomain.match_full(b"a"*63 + b"." + b"b"*63))

        self.assertFalse(SubDomain.match_full(b""))
        self.assertFalse(SubDomain.match_full(b" "))
        self.assertFalse(SubDomain.match_full(b"a..b"))
        self.assertFalse(SubDomain.match_full(b"a.-.b"))
        self.assertFalse(SubDomain.match_full(b"a.1.b"))
        self.assertFalse(SubDomain.match_full(b"a"*64 + b"." + b"b"*63))


class TestDomain(TestCase):
    def test_domain(self) -> None:
        self.assertTrue(Domain.match_full(b"a"))
        self.assertTrue(Domain.match_full(b" "))

        long_domain = b".".join([b"a"*63]*4)
        self.assertEqual(len(long_domain), 255)
        self.assertTrue(Domain.match_full(long_domain))

        longer_domain = b".".join([b"a"*63]*5)
        self.assertFalse(Domain.match_full(longer_domain))

        match_result = Domain.match_start(longer_domain)
        assert match_result is not None
        self.assertEqual(match_result.length, len(long_domain))

        long_domain = b".".join([b"a"*9]*26)
        self.assertEqual(len(long_domain), 259)

        match_result = Domain.match_start(long_domain)
        assert match_result is not None
        self.assertEqual(match_result.length, 255)

        # What if the 255th character is a dot?

        long_domain = b"".join([b"a"*50 + b"."]*5)
        self.assertEqual(len(long_domain), 255)
        self.assertFalse(Domain.match_full(long_domain))

        match_result = Domain.match_start(long_domain)
        assert match_result is not None
        self.assertEqual(match_result.length, 254)
