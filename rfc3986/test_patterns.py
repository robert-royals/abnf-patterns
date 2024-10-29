from unittest import TestCase

from generic import MatchResult
from rfc3986.patterns import (
    DecOctet,
    H16,
    IPv4Address,
    IPv6Address,
    LS32,
)


class TestH16(TestCase):
    def test_h16(self) -> None:
        # 1 to 4 hex characters

        self.assertTrue(H16.match_full(b"1"))
        self.assertTrue(H16.match_full(b"1A"))
        self.assertTrue(H16.match_full(b"1A"))
        self.assertTrue(H16.match_full(b"1AB"))
        self.assertTrue(H16.match_full(b"0ABF"))
        self.assertTrue(H16.match_full(b"123f"))
        self.assertTrue(H16.match_full(b"ffff"))
        self.assertTrue(H16.match_full(b"a"))

        self.assertFalse(H16.match_full(b""))
        self.assertFalse(H16.match_full(b"1."))
        self.assertFalse(H16.match_full(b"0ABF1"))

        self.assertIsNotNone(H16.match_start(b"0ABC1"))
        self.assertIsNone(H16.match_start(b" 0ABC1"))


class TestDecOctet(TestCase):
    def test_dec_single_digit(self) -> None:
        for i in range(10):
            self.assertTrue(DecOctet.match_full(str(i).encode()))
            # Check can't precede number with '0'
            self.assertFalse(DecOctet.match_full(b"0" + str(i).encode()))
            match_result = DecOctet.match_start(b"0" + str(i).encode())
            self.assertIsNotNone(match_result)
            assert isinstance(match_result, MatchResult)
            self.assertEqual(match_result.length, 1)

        self.assertFalse(DecOctet.match_full(b""))
        self.assertFalse(DecOctet.match_full(b"."))
        self.assertFalse(DecOctet.match_full(b"_"))
        self.assertFalse(DecOctet.match_full(b"-1"))

    def test_dec_two_digits(self) -> None:
        for i in range(10, 100):
            self.assertTrue(DecOctet.match_full(str(i).encode()))

        # in these cases, the string value will be things like 259 where
        # the first two bytes will match the ABNF, so we want to still pick
        # these up to be faithful to the definition, but only matching the
        # first two code points:
        for i in range(256, 299):
            match_result = DecOctet.match_start(str(i).encode())
            self.assertIsNotNone(match_result)
            assert isinstance(match_result, MatchResult)
            self.assertEqual(match_result.length, 2)

    def test_dec_three_digits(self) -> None:
        for i in range(100, 256):
            self.assertTrue(DecOctet.match_full(str(i).encode()))

    def test_too_big(self) -> None:
        self.assertFalse(DecOctet.match_full(b"1000"))
        for i in range(256, 1000):
            self.assertFalse(DecOctet.match_full(str(i).encode()))


class TestIPv4Address(TestCase):
    def test_ipv4_address(self) -> None:
        self.assertTrue(IPv4Address.match_full(b"0.0.0.0"))
        self.assertTrue(IPv4Address.match_full(b"1.1.1.1"))
        self.assertTrue(IPv4Address.match_full(b"255.255.255.255"))
        self.assertTrue(IPv4Address.match_full(b"1.10.19.255"))
        self.assertTrue(IPv4Address.match_full(b"127.0.0.1"))

        self.assertFalse(IPv4Address.match_full(b"0.0.256.0"))
        self.assertFalse(IPv4Address.match_full(b"0.0.0.259"))
        self.assertFalse(IPv4Address.match_full(b"0.0.1000.0"))
        self.assertFalse(IPv4Address.match_full(b"0.0.01.0"))
        self.assertFalse(IPv4Address.match_full(b"0.0.0.00"))
        self.assertFalse(IPv4Address.match_full(b"0.0.0.0.0"))
        self.assertFalse(IPv4Address.match_full(b"0.0.0 .0"))
        self.assertFalse(IPv4Address.match_full(b"0.0..0"))
        self.assertFalse(IPv4Address.match_full(b".0.0.0.0"))
        self.assertFalse(IPv4Address.match_full(b"..0.0.0"))


class TestLS32(TestCase):
    def test_h16_pairs(self) -> None:
        # Test the cases where it is h16:h16
        self.assertTrue(LS32.match_full(b"1:1"))
        self.assertTrue(LS32.match_full(b"FFFF:1"))
        self.assertTrue(LS32.match_full(b"FFFF:abcd"))
        self.assertTrue(LS32.match_full(b"abc:123"))
        self.assertTrue(LS32.match_full(b"00:01"))

        self.assertFalse(LS32.match_full(b"1111"))
        self.assertFalse(LS32.match_full(b"1111:"))
        self.assertFalse(LS32.match_full(b":1111"))
        self.assertFalse(LS32.match_full(b"11111:1"))
        self.assertFalse(LS32.match_full(b"1111 : 1"))

        self.assertIsNotNone(LS32.match_start(b"1:11:"))

    def test_ipv4_address(self) -> None:
        # Test that it matches some IPv4 addresses also
        self.assertTrue(LS32.match_full(b"0.0.0.0"))
        self.assertTrue(LS32.match_full(b"255.255.255.255"))
        self.assertTrue(LS32.match_full(b"1.2.11.255"))

        self.assertFalse(LS32.match_full(b"0.256.0.0"))


class TestIPv6Address(TestCase):
    def test_ipv6_address(self) -> None:
        # First some arbitrary examples.
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0::"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0::fff"))

        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0:0:"))
        self.assertFalse(IPv6Address.match_full(b"abcd"))
        self.assertFalse(IPv6Address.match_full(b"abcd:"))
        self.assertFalse(IPv6Address.match_full(b":abcd"))

        self.assertTrue(IPv6Address.match_full(b"1080:0:0:0:8:800:200C:417A"))
        self.assertTrue(IPv6Address.match_full(b"1080::8:800:200C:417A"))
        self.assertTrue(IPv6Address.match_full(b"FF01:0:0:0:0:0:0:101"))
        self.assertTrue(IPv6Address.match_full(b"FF01::101"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0:0:1"))
        self.assertTrue(IPv6Address.match_full(b"0::1"))

        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0:13.1.68.3"))
        self.assertTrue(IPv6Address.match_full(b"::13.1.68.3"))
        self.assertTrue(
            IPv6Address.match_full(b"0:0:0:0:0:FFFF:129.144.52.38")
        )
        self.assertTrue(IPv6Address.match_full(b"::FFFF:129.144.52.38"))

        self.assertFalse(IPv6Address.match_full(b"::0:0.0.0.0:0"))

        # Next we cover every abnf pattern to check they match

        # 6 ( h16 ":" ) ls32:
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0:0:0"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0:fff:fff"))
        self.assertTrue(IPv6Address.match_full(b"0:1:2:3:a:B:fff:fff"))
        self.assertTrue(IPv6Address.match_full(b"012:1:2:3:a:B:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0:255.255.255.255"))

        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0:0:255.0.256.255"))

        # "::" [ h16 / *5( h16 ":" ) ls32 ]
        self.assertTrue(IPv6Address.match_full(b"::"))
        self.assertTrue(IPv6Address.match_full(b"::0"))
        self.assertTrue(IPv6Address.match_full(b"::0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0:0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0:0:0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0:0:0:0:0.0.0.0"))
        self.assertFalse(IPv6Address.match_full(b"::0:0:0:0:0:0:0.0.0.0"))

        self.assertTrue(IPv6Address.match_full(b"::0:0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0:0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0:0:0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0:0:0:0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0:0:0:0:0"))
        self.assertTrue(IPv6Address.match_full(b"::0:0:0:0:0:0:0"))

        ipv6_addr = "::0:0:0:0:0:0:0"
        match_result = IPv6Address.match_start(b"::0:0:0:0:0:0:0.0.0.0")
        self.assertIsNotNone(match_result)
        assert isinstance(match_result, MatchResult)
        self.assertEqual(match_result.length, len(ipv6_addr))

        # ( h16 ":" ) ":" [ h16 / *4( h16 ":" ) ls32 ]

        self.assertTrue(IPv6Address.match_full(b"0::"))
        self.assertTrue(IPv6Address.match_full(b"0::ffff"))
        self.assertTrue(IPv6Address.match_full(b"0::0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0::FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0::0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0::0:FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0::0:0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0::0:0:FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0::0:0:0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0::0:0:0:FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0::0:0:0:0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0::0:0:0:0:FFFF:ffff"))
        self.assertFalse(IPv6Address.match_full(b"0::0:0:0:0:0:0.0.0.0"))
        self.assertFalse(IPv6Address.match_full(b"0::0:0:0:0:0:FFFF:ffff"))

        # 2( h16 ":" ) ":" [ h16 / *3( h16 ":" ) ls32 ]
        self.assertTrue(IPv6Address.match_full(b"0:0::"))
        self.assertTrue(IPv6Address.match_full(b"0:0::ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0::0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0::FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0::0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0::0:FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0::0:0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0::0:0:FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0::0:0:0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0::0:0:0:FFFF:ffff"))
        self.assertFalse(IPv6Address.match_full(b"0:0::0:0:0:0:0.0.0.0"))
        self.assertFalse(IPv6Address.match_full(b"0:0::0:0:0:0:FFFF:ffff"))

        # 3( h16 ":" ) ":" [ h16 / *2( h16 ":" ) ls32 ]
        self.assertTrue(IPv6Address.match_full(b"0:0:0::"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0::ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0::0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0::FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0::0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0::0:FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0::0:0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0::0:0:FFFF:ffff"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0::0:0:0:0.0.0.0"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0::0:0:0:FFFF:ffff"))

        # 4( h16 ":" ) ":" [ h16 / *1( h16 ":" ) ls32 ]
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0::"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0::ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0::0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0::FFFF:ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0::0:0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0::0:FFFF:ffff"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0::0:0:0.0.0.0"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0::0:0:FFFF:ffff"))

        # 5( h16 ":" ) ":" [ h16 / ls32 ]
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0::"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0::ffff"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0::0.0.0.0"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0::FFFF:ffff"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0::0:0.0.0.0"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0::0:FFFF:ffff"))

        # 6( h16 ":" ) ":" [ h16 ]
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0::"))
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0::ffff"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0:0::0.0.0.0"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0:0::FFFF:ffff"))

        # 7( h16 ":" ) ":"
        self.assertTrue(IPv6Address.match_full(b"0:0:0:0:0:0:0::"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0:0:0::ffff"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0:0:0::0.0.0.0"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0:0:0::0"))
        self.assertFalse(IPv6Address.match_full(b"0:0:0:0:0:0:0:0::"))
