from unittest import TestCase

from generic import MatchResult
from rfc2616.patterns import (
    CRLF,
    LWS,

    Octet,
    LoAlpha,
    UpAlpha,
    Alpha,
    Digit,
)


class TestUPALPHA(TestCase):
    def test_upalpha(self) -> None:
        self.assertTrue(UpAlpha.match_full(b"B"))
        self.assertTrue(UpAlpha.match_full(b"A"))
        self.assertTrue(UpAlpha.match_full(b"Z"))
        self.assertFalse(UpAlpha.match_full(b"a"))
        self.assertFalse(UpAlpha.match_full(b"."))
        self.assertFalse(UpAlpha.match_full(b"AA"))
        self.assertTrue(UpAlpha.match_start(b"AA"))
        self.assertFalse(UpAlpha.match_full(b""))
        self.assertFalse(UpAlpha.match_start(b""))


class TestLOALPHA(TestCase):
    def test_loalpha(self) -> None:
        self.assertTrue(LoAlpha.match_full(b"b"))
        self.assertTrue(LoAlpha.match_full(b"a"))
        self.assertTrue(LoAlpha.match_full(b"z"))
        self.assertFalse(LoAlpha.match_full(b"A"))
        self.assertFalse(LoAlpha.match_full(b"."))
        self.assertFalse(LoAlpha.match_full(b"aa"))
        self.assertFalse(LoAlpha.match_full(b""))


class TestALPHA(TestCase):
    def test_alpha(self) -> None:
        self.assertTrue(Alpha.match_full(b"a"))
        self.assertTrue(Alpha.match_full(b"A"))
        self.assertTrue(Alpha.match_full(b"z"))
        self.assertTrue(Alpha.match_full(b"Z"))
        self.assertFalse(Alpha.match_full(b"1"))
        self.assertFalse(Alpha.match_full(b"\0"))
        self.assertFalse(Alpha.match_full(b""))
        self.assertFalse(Alpha.match_full(b"AA"))


class TestOctet(TestCase):
    def test_octet(self) -> None:
        for i in range(256):
            self.assertTrue(Octet.match_full(bytes([i])))
        self.assertFalse(Octet.match_full(b""))
        self.assertFalse(Octet.match_full(b"AA"))
        self.assertIsNotNone(Octet.match_start(b"AA"))


class TestDigit(TestCase):
    def test_digit(self) -> None:
        for i in range(10):
            self.assertTrue(Digit.match_full(str(i).encode()))
        self.assertFalse(Digit.match_full(b"a"))
        self.assertFalse(Digit.match_full(b""))
        self.assertFalse(Digit.match_full(b"00"))


class TestCRLF(TestCase):
    def test_crlf(self) -> None:
        self.assertTrue(CRLF.match_full(b"\r\n"))
        self.assertFalse(CRLF.match_full(b"\n\r"))
        self.assertFalse(CRLF.match_full(b"\r"))
        self.assertFalse(CRLF.match_full(b""))

        self.assertIsNotNone(CRLF.match_start(b"\r\n..."))
        self.assertIsNotNone(CRLF.match_from(b".\r\n...", 1))


class TestLWS(TestCase):
    def test_lws(self) -> None:
        # Matches any series of spaces and tabs, with an optional preceding
        # \r\n (but no more than one of these)
        self.assertTrue(LWS.match_full(b" "))
        self.assertTrue(LWS.match_full(b"\t"))
        self.assertTrue(LWS.match_full(b"  \t   "))
        self.assertTrue(LWS.match_full(b"   \t\t\t   "))
        self.assertTrue(LWS.match_full(b"\r\n "))
        self.assertTrue(LWS.match_full(b"\r\n\t"))
        self.assertTrue(LWS.match_full(b"\r\n  \t   "))
        self.assertTrue(LWS.match_full(b"\r\n   \t\t\t   "))

        self.assertFalse(LWS.match_full(b"\r\n"))
        self.assertFalse(LWS.match_full(b"\r\n a"))
        self.assertFalse(LWS.match_full(b"\r\n\r\n "))
        self.assertFalse(LWS.match_full(b"\r\n \r\n "))
        self.assertFalse(LWS.match_full(b"\n  "))
        self.assertFalse(LWS.match_full(b"\r  "))
        self.assertFalse(LWS.match_full(b"  \r\n"))

        self.assertIsNotNone(LWS.match_start(b"\r\n a"))
        self.assertIsNone(LWS.match_start(b".\r\n"))
        match_result = LWS.match_start(b" \r\n")
        assert isinstance(match_result, MatchResult)
        self.assertEqual(match_result.length, 1)
