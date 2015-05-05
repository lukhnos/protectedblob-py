import unittest

from protectedblob.cipher_suites import AES256CBCSHA256


class TestAlgorithmSuite(unittest.TestCase):

    def setUp(self):
        self.suite = AES256CBCSHA256
        self.key = b'\0' * self.suite.KEY_SIZE

    def test_roundtrip(self):
        plaintext = b'hello, world'
        encrypted_data = self.suite.encrypt(self.key, plaintext)
        decrypted_text = self.suite.decrypt(self.key, encrypted_data)
        self.assertEqual(decrypted_text, plaintext)
