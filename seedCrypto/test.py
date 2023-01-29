import unittest
from .seed import SeedRoundKey, SeedEncrypt, SeedDecrypt

testcases = [
    {
        'key': b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f',
        'plainText': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        'cipherText': b'\xc1\x1f"\xf2\x01@PP\x84H5\x97\xe47\x0fC'
    },
    {
        'key': b'G\x06H\x08Q\xe6\x1b\xe8]t\xbf\xb3\xfd\x95a\x85',
        'plainText': b'\x83\xa2\xf8\xa2\x88d\x1f\xb9\xa4\xe9\xa5\xcc/\x13\x1c}',
        'cipherText': b'\xeeT\xd1>\xbc\xaepm"k\xc3\x14,\xd4\rJ'
    },
    {
        'key': b'(\xdb\xc3\xbcI\xff\xd8}\xcf\xa5\t\xb1\x1dB+\xe7',
        'plainText': b'\xb4\x1ek\xe2\xeb\xa8J\x14\x8e.\xed\x84Y<^\xc7',
        'cipherText': b'\x9b\x9b{\xfc\xd1\x81<\xb9]\x0b6\x18\xf4\x0fQ"'
    }
]


class SeedTest(unittest.TestCase):
    def test_encrypt(self):
        for tcase in testcases:
            roundKey = SeedRoundKey(tcase["key"])
            encrypted = SeedEncrypt(roundKey, tcase["plainText"])
            self.assertEqual(encrypted, tcase["cipherText"])

    def test_decrypt(self):
        for tcase in testcases:
            roundKey = SeedRoundKey(tcase["key"])
            decrypted = SeedDecrypt(roundKey, tcase["cipherText"])
            self.assertEqual(decrypted, tcase["plainText"])


if __name__ == '__main__':
    unittest.main()
