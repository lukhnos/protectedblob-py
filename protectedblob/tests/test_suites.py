import unittest

from protectedblob.cipher_suites import AES256CBCSHA256
from protectedblob.cipher_suites import EncryptedData
from protectedblob.cipher_suites import HMACMismatchException


class TestAlgorithmSuite(unittest.TestCase):

    def setUp(self):
        self.suite = AES256CBCSHA256
        self.key = b'\0' * self.suite.KEY_SIZE

    def test_roundtrip(self):
        plaintext = b'hello, world'
        encrypted_data = self.suite.encrypt(self.key, plaintext)
        decrypted_text = self.suite.decrypt(self.key, encrypted_data)
        self.assertEqual(decrypted_text, plaintext)

    def test_corrupt_data(self):
        plaintext = b'hello, world'
        encrypted_data = self.suite.encrypt(self.key, plaintext)
        corrupt_data = EncryptedData(
            iv=encrypted_data.iv,
            ciphertext=b'\0' * len(encrypted_data.ciphertext),
            hmac=encrypted_data.hmac)

        with self.assertRaises(HMACMismatchException):
            self.suite.decrypt(self.key, corrupt_data)
