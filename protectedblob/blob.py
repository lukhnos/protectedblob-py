from protectedblob.cipher_suites import AES256CBCSHA256
from protectedblob.cipher_suites import EncryptedData
from protectedblob.key_derivation import PBKDF2SHA256AES256
from protectedblob.key_derivation import EncryptedKey
from protectedblob.util import dict_to_namedtuple_with_base64_fields
from protectedblob.util import namedtuple_to_dict_with_base64_bytes


class PassphraseProtectedBlob(object):
    VERSION = '1'

    def __init__(self, cipher_suite, kdf):
        self.version = self.VERSION
        self.cipher_suite = cipher_suite
        self.kdf = kdf
        self.encrypted_data = None
        self.encrypted_key = None

    def to_dict(self):
        return dict(
            version=self.VERSION,
            cipher_suite=self.cipher_suite.SUITE_NAME,
            kdf=self.kdf.KDF_NAME,
            encrypted_data=namedtuple_to_dict_with_base64_bytes(
                self.encrypted_data),
            encrypted_key=namedtuple_to_dict_with_base64_bytes(
                self.encrypted_key)
        )

    @classmethod
    def from_dict(cls, d):
        keys = set((
            'version',
            'cipher_suite',
            'kdf',
            'encrypted_data',
            'encrypted_key'
        ))
        if set(d.keys()) != keys:
            raise ValueError('Keys mismatch')
        if d['version'] != cls.VERSION:
            raise ValueError('Unsupported version: %s' % d['version'])
        if d['cipher_suite'] != AES256CBCSHA256.SUITE_NAME:
            raise ValueError('Unsupported cipher suite: %s' % (
                d['cipher_suite']))
        if d['kdf'] != PBKDF2SHA256AES256.KDF_NAME:
            raise ValueError('Unsupported KDF: %s' % d['kdf'])

        data = dict_to_namedtuple_with_base64_fields(
            d['encrypted_data'], EncryptedData, EncryptedData._fields)
        key = dict_to_namedtuple_with_base64_fields(
            d['encrypted_key'], EncryptedKey, ['salt', 'encrypted_key'])

        blob = PassphraseProtectedBlob(AES256CBCSHA256, PBKDF2SHA256AES256)
        blob.encrypted_key = key
        blob.encrypted_data = data
        return blob

    def get_plaintext(self, passphrase):
        key = self.kdf.decrypt_key(self.encrypted_key, passphrase)
        plaintext = self.cipher_suite.decrypt(key, self.encrypted_data)
        return plaintext

    def populate_with_plaintext(self, passphrase, plaintext, rounds=0):
        if rounds > 0:
            kdf_rounds = rounds
        else:
            kdf_rounds = self.kdf.DEFAULT_ROUNDS

        key = self.cipher_suite.generate_key()
        self.encrypted_key = self.kdf.generate_encrypted_key(
            key, passphrase, kdf_rounds)

        self.encrypted_data = self.cipher_suite.encrypt(key, plaintext)

    def change_passphrase(self, old_passphrase, new_passphrase, rounds=0):
        if self.encrypted_key is None:
            raise AssertionError('Must have existing key in place')

        if rounds > 0:
            kdf_rounds = rounds
        else:
            kdf_rounds = self.encrypted_key.rounds

        key = self.kdf.decrypt_key(self.encrypted_key, old_passphrase)
        self.encrypted_key = self.kdf.generate_encrypted_key(
            key, new_passphrase, kdf_rounds)
