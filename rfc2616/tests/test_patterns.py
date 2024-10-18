from unittest import TestCase

from rfc2616.patterns import upalpha


class TestUPALPHA(TestCase):
    def test_upalpha(self) -> None:
        self.assertTrue(upalpha(b"B"))
        self.assertTrue(upalpha(b"A"))
        self.assertTrue(upalpha(b"Z"))
        self.assertFalse(upalpha(b"a"))
        self.assertFalse(upalpha(b"."))
        self.assertFalse(upalpha(b"AA"))
        self.assertFalse(upalpha(b""))
