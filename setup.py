from setuptools import setup

import protectedblob


setup(
    name='protectedblob',
    version=protectedblob.__version__,
    author='Lukhnos Liu',
    author_email='lukhnos@lukhnos.org',
    license='MIT',
    packages=['protectedblob'],
    install_requires=[
        'pycrypto >= 2.6.1'
    ],
    test_suite='protectedblob.tests',
    entry_points={
        'console_scripts': ['protectedblob = protectedblob.cmd:main']
    })
