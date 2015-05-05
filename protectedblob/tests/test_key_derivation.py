# -*- coding: utf-8 -*-
import unittest

from protectedblob.key_derivation import PBKDF2SHA256AES256


class TestPBKDF2SHA256AES256(unittest.TestCase):
    def test_roundtrip(self):
        key = b'\0' * 32
        passphrase = b'hello'
        rounds = 1000

        encrypted_key = PBKDF2SHA256AES256.generate_encrypted_key(
            key, passphrase, rounds)
        decripted_key = PBKDF2SHA256AES256.decrypt_key(
            encrypted_key, passphrase)

        self.assertEqual(key, decripted_key)

    def test_unicode_key_derivation(self):
        salt = b'\0' * PBKDF2SHA256AES256.SALT_SIZE
        rounds = 1000
        p1 = 'hello, 世界'
        p2 = u'hello, 世界'
        k1 = PBKDF2SHA256AES256.derive_key(salt, p1, rounds)
        k2 = PBKDF2SHA256AES256.derive_key(salt, p2, rounds)
        self.assertEqual(k1, k2)
