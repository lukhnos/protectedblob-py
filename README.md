# protectedblob

[![Build Status](https://travis-ci.org/lukhnos/protectedblob-py.svg?branch=master)](https://travis-ci.org/lukhnos/protectedblob-py)

protectedblob is a library and a utility that can create a
passphrase-protected blob from a plaintext as well as decrypt it.

This is still a work in progress. I am working on
[a mobile password manager](https://github.com/lukhnos/PocketPasswords)
that depends on it. This project is also an exercise in creating a library
that supports both Python 2.7 and 3.4, among many other library development
drills.

Also please be warned that this code has not been through any security
review. Use this at your own risk.


## Supported Platforms

This is currently tested only on OS X, but it should work on general *NIX.
There's currently no Windows support.

The code can be used with Python 2.6.9, 2.7, and 3.4.


## Usage

To install:

    python setup.py install

It's very likely that you'll need `sudo`:

    sudo python setup.py install

This library depends on [PyCrypto](https://www.dlitz.net/software/pycrypto/),
which in turn requires a C compiler to build. For OS X users, this means you
have to have Xcode or Xcode Command Line Tools installed (so that you have the
Clang C/C++ compiler). On Linux, you'll need gcc, and, on a lot of
distributions, a corresponding Python development package, such as
`python-devel` on CentOS or `python-dev` on Debian or Ubuntu.

Alternatively, install the code in development mode:

    python setup.py develop

To encrypt a file:

    protectedblob encrypt --input <input file> --output <output file>

You'll be prompted for the passphrase twice. There's also an optional
`--rounds` argument to override the default number of rounds.

To decrypt:

    protectedblob decrypt --input <input file> --output <output file>


## High-Level Description

A passphrased-protected blob has two types of data: An encrypted key, and the
actual ciphertext. Before encrypting the plaintext, we generate a random key.
This makes it possible to change passphrase later.

The random key is encrypted with another key derived from the supplied
passphrase. A key-derivation function (KDF) is used. To increase the strength
of the derived key, many rounds are used.

The key derivation function is PBKDF2 with the underlying PDF being SHA-256. A
random salt is also generated. The default number of rounds is 65536, although
more should be used on fast computers.

The real encryption key is encrypted using AES-256 (128-bit block, 256-bit
key) in ECB mode. We actually don't use the encryption key directly. Rather,
we derive two more keys from it: One for the AES-256 cipher, another for the
HMAC function. The two keys are derived by using an AES-256 in ECB mode to
encrypt 32 bytes of 0x00's and 32 bytes of 0x01's, respectively. The plaintext
is then encrypted using AES-256 in CBC mode with a 128-bit IV (initialization
vector).

The library implements authenticated encryption. The HMAC function is SHA-256,
and the HMAC is created from the ciphertext (so encrypt-then-mac).
