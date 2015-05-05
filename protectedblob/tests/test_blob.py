import unittest

from protectedblob.blob import PassphraseProtectedBlob
from protectedblob.cipher_suites import AES256CBCSHA256
from protectedblob.key_derivation import PBKDF2SHA256AES256


class TestPassphraseProtectedBlob(unittest.TestCase):
    def test_roundtrip(self):
        plaintext = b'hello, world!'
        passphrase = 'foobar'
        blob = PassphraseProtectedBlob(
            cipher_suite=AES256CBCSHA256,
            kdf=PBKDF2SHA256AES256)
        blob.populate_with_plaintext(passphrase, plaintext, rounds=1000)
        decrypted_text = blob.get_plaintext(passphrase)
        self.assertEqual(decrypted_text, plaintext)

    def test_change_passphrase(self):
        plaintext = b'hello, world!'
        passphrase = 'foobar'
        blob = PassphraseProtectedBlob(
            cipher_suite=AES256CBCSHA256,
            kdf=PBKDF2SHA256AES256)
        blob.populate_with_plaintext(passphrase, plaintext, rounds=1000)
        decrypted_text = blob.get_plaintext(passphrase)
        self.assertEqual(decrypted_text, plaintext)

        new_passphrase = 'barfoo'
        blob.change_passphrase(passphrase, new_passphrase)
        new_decrypted_text = blob.get_plaintext(new_passphrase)
        self.assertEqual(new_decrypted_text, decrypted_text)
