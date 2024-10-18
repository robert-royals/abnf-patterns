from unittest import TestCase

from rfc2616.patterns import (
    octet,
    loalpha,
    upalpha,
    alpha,
)


class TestUPALPHA(TestCase):
    def test_upalpha(self) -> None:
        self.assertTrue(upalpha(b"B"))
        self.assertTrue(upalpha(b"A"))
        self.assertTrue(upalpha(b"Z"))
        self.assertFalse(upalpha(b"a"))
        self.assertFalse(upalpha(b"."))
        self.assertFalse(upalpha(b"AA"))
        self.assertFalse(upalpha(b""))


class TestLOALPHA(TestCase):
    def test_loalpha(self) -> None:
        self.assertTrue(loalpha(b"b"))
        self.assertTrue(loalpha(b"a"))
        self.assertTrue(loalpha(b"z"))
        self.assertFalse(loalpha(b"A"))
        self.assertFalse(loalpha(b"."))
        self.assertFalse(loalpha(b"aa"))
        self.assertFalse(loalpha(b""))


class TestALPHA(TestCase):
    def test_alpha(self) -> None:
        self.assertTrue(alpha(b"a"))
        self.assertTrue(alpha(b"A"))
        self.assertTrue(alpha(b"z"))
        self.assertTrue(alpha(b"Z"))
        self.assertFalse(alpha(b"1"))
        self.assertFalse(alpha(b"\0"))
        self.assertFalse(alpha(b""))
        self.assertFalse(alpha(b"AA"))


class TestOctet(TestCase):
    def test_octet(self) -> None:
        for i in range(256):
            self.assertTrue(octet(bytes([i])))
        self.assertFalse(octet(b""))
        self.assertFalse(octet(b"AA"))
