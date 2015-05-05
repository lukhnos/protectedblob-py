import argparse
import getpass
import io
import json
import sys

from protectedblob.blob import PassphraseProtectedBlob
from protectedblob.cipher_suites import AES256CBCSHA256
from protectedblob.key_derivation import PBKDF2SHA256AES256


def encrypt(args):
    p1 = getpass.getpass('enter passphrase: ')
    p2 = getpass.getpass('repeat passphrase: ')

    if p1 != p2:
        sys.stderr.write('passphrase does not match\n')
        return 1

    if len(p1) == 0 or len(p2) == 0:
        sys.stderr.write('passphrase must not be empty\n')
        return 1

    with io.open(args.input, 'rb') as f:
        plaintext = f.read()

    blob = PassphraseProtectedBlob(AES256CBCSHA256, PBKDF2SHA256AES256)
    blob.populate_with_plaintext(p1, plaintext)

    with io.open(args.output, 'w', encoding='utf-8') as f:
        if sys.version_info[0] == 2:
            f.write(unicode(json.dumps(blob.to_dict())))
        else:
            json.dump(blob.to_dict(), f)


def decrypt(args):
    with io.open(args.input, 'r', encoding='utf-8') as f:
        d = json.load(f, encoding='utf-8')
    blob = PassphraseProtectedBlob.from_dict(d)
    passphrase = getpass.getpass('enter passphrase: ')
    plaintext = blob.get_plaintext(passphrase)
    with io.open(args.output, 'wb') as f:
        f.write(plaintext)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True

    parser_encrypt = subparsers.add_parser('encrypt')
    parser_encrypt.add_argument('--input', required=True)
    parser_encrypt.add_argument('--output', required=True)
    parser_encrypt.add_argument(
        '--rounds', type=int, default=PBKDF2SHA256AES256.DEFAULT_ROUNDS)
    parser_encrypt.set_defaults(func=encrypt)

    parser_decrypt = subparsers.add_parser('decrypt')
    parser_decrypt.add_argument('--input', required=True)
    parser_decrypt.add_argument('--output', required=True)
    parser_decrypt.set_defaults(func=decrypt)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    sys.exit(main())
