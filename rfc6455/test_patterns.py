from unittest import TestCase

from generic import MatchResult

from rfc6455.patterns import (
    Base64Char,
    Base64Data,
    Base64Padding,
    Base64ValueNonEmpty,
)


class TestB64Char(TestCase):
    def test_b64char(self) -> None:
        self.assertTrue(Base64Char.match_full(b"a"))
        self.assertTrue(Base64Char.match_full(b"Z"))
        self.assertTrue(Base64Char.match_full(b"1"))
        self.assertTrue(Base64Char.match_full(b"+"))
        self.assertTrue(Base64Char.match_full(b"/"))
        self.assertFalse(Base64Char.match_full(b"-"))
        self.assertFalse(Base64Char.match_full(b"@"))
        self.assertFalse(Base64Char.match_full(b""))
        self.assertFalse(Base64Char.match_full(b"("))
        self.assertFalse(Base64Char.match_full(b"aa"))

        self.assertIsNotNone(Base64Char.match_start(b"aa"))
        self.assertIsNone(Base64Char.match_start(b"!A"))


class TestB64Data(TestCase):
    def test_b64data(self) -> None:
        self.assertTrue(Base64Data.match_full(b"aaaa"))
        self.assertTrue(Base64Data.match_full(b"aA0+"))
        self.assertTrue(Base64Data.match_full(b"/Az+"))
        self.assertFalse(Base64Data.match_full(b"/Az_"))
        self.assertFalse(Base64Data.match_full(b"abc@"))
        self.assertFalse(Base64Data.match_full(b"abc"))
        self.assertFalse(Base64Data.match_full(b"abc "))
        self.assertFalse(Base64Data.match_full(b""))

        self.assertIsNotNone(Base64Data.match_start(b"AAAA-"))
        self.assertIsNotNone(Base64Data.match_start(b"AAAAa"))
        self.assertIsNone(Base64Data.match_start(b"-AAAA"))


class TestB64Padding(TestCase):
    def test_b64padding(self) -> None:
        self.assertTrue(Base64Padding.match_full(b"AA=="))
        self.assertTrue(Base64Padding.match_full(b"AAb="))
        self.assertFalse(Base64Padding.match_full(b"aa=a"))
        self.assertFalse(Base64Padding.match_full(b"a==="))
        self.assertFalse(Base64Padding.match_full(b"aaaa"))
        self.assertFalse(Base64Padding.match_full(b"aaa"))
        self.assertFalse(Base64Padding.match_full(b"aa="))
        self.assertFalse(Base64Padding.match_full(b"aa==="))

        self.assertIsNotNone(Base64Padding.match_start(b"aa==="))
        self.assertIsNotNone(Base64Padding.match_start(b"aab=="))
        self.assertIsNone(Base64Padding.match_start(b"a==="))
        self.assertIsNone(Base64Padding.match_start(b"=aaa"))


class TestB64ValueNonEmpty(TestCase):
    def test_b64_value_non_empty(self) -> None:
        self.assertTrue(Base64ValueNonEmpty.match_full(b"AAAA"))
        self.assertTrue(Base64ValueNonEmpty.match_full(b"AAA="))
        self.assertTrue(Base64ValueNonEmpty.match_full(b"aaaabbbb"))
        self.assertTrue(Base64ValueNonEmpty.match_full(b"aaaabb=="))
        self.assertTrue(Base64ValueNonEmpty.match_full(b"aaaabb+/1234"))
        self.assertTrue(Base64ValueNonEmpty.match_full(b"aaaabb+/1234uuu="))
        self.assertTrue(Base64ValueNonEmpty.match_full(
            b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        ))
        self.assertTrue(Base64ValueNonEmpty.match_full(
            b"dGhlIHNhbXBsZSBub25jZQ=="
        ))
        self.assertTrue(Base64ValueNonEmpty.match_full(
            b"ZWRuYW1vZGU6bm9jYXBlcyE="
        ))
        self.assertTrue(Base64ValueNonEmpty.match_full(
            b"AQIDBAUGBwgJCgsMDQ4PEC=="
        ))
        self.assertTrue(Base64ValueNonEmpty.match_full(
            b"Um9iZXJ0IFJveWFscw=="
        ))
        self.assertFalse(Base64ValueNonEmpty.match_full(b""))
        self.assertFalse(Base64ValueNonEmpty.match_full(b"aaaaa"))
        self.assertFalse(Base64ValueNonEmpty.match_full(b"aaaa="))
        self.assertFalse(Base64ValueNonEmpty.match_full(b"aaaa===="))
        self.assertFalse(Base64ValueNonEmpty.match_full(b"hh==00=="))

        match_result = Base64ValueNonEmpty.match_start(b"aaaabb==...")
        assert isinstance(match_result, MatchResult)
        self.assertEqual(match_result.length, 8)

        match_result = Base64ValueNonEmpty.match_start(b"aa==1234")
        self.assertIsNotNone(match_result)
        assert isinstance(match_result, MatchResult)
        self.assertEqual(match_result.length, 4)

        match_result = Base64ValueNonEmpty.match_start(b"a"*25)
        self.assertIsNotNone(match_result)
        assert isinstance(match_result, MatchResult)
        self.assertEqual(match_result.length, 24)
