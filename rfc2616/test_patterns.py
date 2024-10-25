from unittest import TestCase

from rfc2616.patterns import (
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
