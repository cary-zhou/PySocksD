#!/usr/bin/env python3
import sys
from setuptools import setup


if sys.version_info[:2] < (3, 4):
    sys.exit('Support Python 3.4 or above only.')

setup(
    name='PySocksD',
    version='0.0.1',
    description='A proxy server which say SOCKSv5.',
    author='sorz',
    author_email='orz@sorz.org',
    packages=['pysocksd'],
    entry_points="""
    [console_scripts]
    pysocksd = pysocksd:main
    """,
)

