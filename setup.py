#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

from sm_crypto import __version__, __author__, __email__

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['pyasn1']

test_requirements = ['pytest>=3', ]

setup(
    name='sm-crypto',
    version=__version__,
    author=__author__,
    author_email=__email__,
    license="MIT license",
    description="china gm cryptography such as sm2,sm3,sm4",
    long_description=readme + '\n\n' + history,
    long_description_content_type='text/x-rst',
    url='https://github.com/hanzhichao/sm-crypto',
    install_requires=requirements,
    include_package_data=True,
    keywords=['sm-crypto', 'sm2', 'gm', 'sm3', 'sm4', 'gmssl'],
    packages=find_packages(include=['sm_crypto', 'sm_crypto.*']),
    test_suite='tests',
    tests_require=test_requirements,
    zip_safe=False,
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
