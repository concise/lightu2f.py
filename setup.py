import sys

if sys.version_info < (3, 5):
    raise NotImplementedError(
            'Sorry, the lowest supported Python version number is 3.5')

from setuptools import setup

setup(
    name='lightu2f',
    version='0.0.1',
    description='A lightweight FIDO U2F relying party library',
    author='Jong-Shian Wu',
    author_email='js@jong.sh',
    url='https://github.com/concise/lightu2f.py',
    license='MIT',
    py_modules=['lightu2f'],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Security',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ],
)
