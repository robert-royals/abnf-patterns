from unittest import TestCase

from rfc2234.patterns import Digit, Alpha, HexDig


class TestDigit(TestCase):
    def test_digit(self) -> None:
        for i in range(10):
            self.assertTrue(Digit.match_full(str(i).encode()))
        self.assertFalse(Digit.match_full(b"a"))
        self.assertFalse(Digit.match_full(b""))
        self.assertFalse(Digit.match_full(b"00"))


class TestAlpha(TestCase):
    def test_alpha(self) -> None:
        self.assertTrue(Alpha.match_full(b"a"))
        self.assertTrue(Alpha.match_full(b"A"))
        self.assertTrue(Alpha.match_full(b"z"))
        self.assertTrue(Alpha.match_full(b"Z"))
        self.assertFalse(Alpha.match_full(b"1"))
        self.assertFalse(Alpha.match_full(b"\0"))
        self.assertFalse(Alpha.match_full(b""))
        self.assertFalse(Alpha.match_full(b"AA"))


class TestHexDig(TestCase):
    def test_hexdig(self) -> None:
        self.assertTrue(HexDig.match_full(b"0"))
        self.assertTrue(HexDig.match_full(b"5"))
        self.assertTrue(HexDig.match_full(b"9"))
        self.assertTrue(HexDig.match_full(b"A"))
        self.assertTrue(HexDig.match_full(b"C"))
        self.assertTrue(HexDig.match_full(b"F"))
        self.assertTrue(HexDig.match_full(b"a"))
        self.assertTrue(HexDig.match_full(b"c"))
        self.assertTrue(HexDig.match_full(b"f"))

        self.assertFalse(HexDig.match_full(b"G"))
        self.assertFalse(HexDig.match_full(b""))
        self.assertFalse(HexDig.match_full(b"AA"))

        self.assertIsNotNone(HexDig.match_start(b"0A"))
        self.assertIsNotNone(HexDig.match_start(b"AA"))
        self.assertIsNotNone(HexDig.match_start(b"aA"))
        self.assertIsNone(HexDig.match_start(b" A"))
