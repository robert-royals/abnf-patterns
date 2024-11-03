from unittest import TestCase

from generic import case_insensitive_compare, literal_compare


class TestLiteralChar(TestCase):
    def test_literal(self) -> None:
        plus_test = literal_compare(b"+")
        self.assertTrue(plus_test.match_full(b"+"))
        self.assertFalse(plus_test.match_full(b"."))
        self.assertFalse(plus_test.match_full(b"++"))
        self.assertFalse(plus_test.match_full(b""))
        self.assertFalse(plus_test.match_full(b"3"))
        self.assertIsNotNone(plus_test.match_start(b"+3"))

        and_test = literal_compare(b"&")
        self.assertTrue(and_test.match_full(b"&"))
        self.assertFalse(and_test.match_full(b"."))
        self.assertIsNotNone(and_test.match_start(b"&&"))

        empty_test = literal_compare(b"")
        self.assertTrue(empty_test.match_full(b""))
        self.assertFalse(empty_test.match_full(b"."))
        self.assertIsNotNone(empty_test.match_start(b"."))

        abc_test = literal_compare(b"abc")
        self.assertTrue(abc_test.match_full(b"abc"))
        self.assertFalse(abc_test.match_full(b"def"))


class TestCaseInsensitiveCompare(TestCase):
    def test_case_insensitive(self) -> None:
        abc_test = case_insensitive_compare(b"abc")

        self.assertTrue(abc_test.match_full(b"abc"))
        self.assertTrue(abc_test.match_full(b"ABC"))
        self.assertTrue(abc_test.match_full(b"aBc"))

        abc_test = case_insensitive_compare(b"aBC")
        self.assertTrue(abc_test.match_full(b"abc"))
        self.assertTrue(abc_test.match_full(b"ABC"))
        self.assertTrue(abc_test.match_full(b"aBc"))

        self.assertFalse(abc_test.match_full(b"123"))
        self.assertFalse(abc_test.match_full(b'!"#'))
        self.assertFalse(abc_test.match_full(bytes([0x81, 0x82, 0x83])))

        a_test = case_insensitive_compare(b"a")

        # Check "a" matches only "a" and "A"
        for i in range(256):
            if i in b"Aa":
                self.assertTrue(a_test.match_full(bytes([i])))
            else:
                self.assertFalse(a_test.match_full(bytes([i])))

        colon_test = case_insensitive_compare(b":")

        # Check ":" only matches ":"
        for i in range(256):
            if i in b":":
                self.assertTrue(colon_test.match_full(bytes([i])))
            else:
                self.assertFalse(colon_test.match_full(bytes([i])))
