from unittest import TestCase

from generic import literal_compare


class TestLiteralChar(TestCase):
    def test_literal(self) -> None:
        plus_test = literal_compare("+")
        self.assertTrue(plus_test.match_full(b"+"))
        self.assertFalse(plus_test.match_full(b"."))
        self.assertFalse(plus_test.match_full(b"++"))
        self.assertFalse(plus_test.match_full(b""))
        self.assertFalse(plus_test.match_full(b"3"))
        self.assertIsNotNone(plus_test.match_start(b"+3"))

        and_test = literal_compare("&")
        self.assertTrue(and_test.match_full(b"&"))
        self.assertFalse(and_test.match_full(b"."))
        self.assertIsNotNone(and_test.match_start(b"&&"))

        empty_test = literal_compare("")
        self.assertTrue(empty_test.match_full(b""))
        self.assertFalse(empty_test.match_full(b"."))
        self.assertIsNotNone(empty_test.match_start(b"."))

        abc_test = literal_compare("abc")
        self.assertTrue(abc_test.match_full(b"abc"))
        self.assertFalse(abc_test.match_full(b"def"))
