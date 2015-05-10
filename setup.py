from setuptools import setup

import protectedblob


setup(
    name='protectedblob',
    version=protectedblob.__version__,
    author='Lukhnos Liu',
    author_email='lukhnos@lukhnos.org',
    description='Create passphrase-protected blobs',
    long_description=open('README.md', 'r').read(),
    license='MIT',
    url='https://github.com/lukhnos/protectedblob-py',
    packages=['protectedblob'],
    install_requires=[
        'pycrypto >= 2.6.1'
    ],
    test_suite='protectedblob.tests',
    entry_points={
        'console_scripts': ['protectedblob = protectedblob.cmd:main']
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Unix',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography'
    ],
)
