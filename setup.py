#! /usr/bin/env python

"""
<Program Name>
  setup.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  December 7, 2016.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  BUILD SOURCE DISTRIBUTION

  The following shell command generates a securesystemslib source archive that
  can be distributed to other users.  The packaged source is saved to the
  'dist' folder in the current directory.

  $ python setup.py sdist


  INSTALLATION OPTIONS

  pip - installing and managing Python packages (recommended):

  # Installing from Python Package Index (https://pypi.python.org/pypi).
  $ pip install securesystemslib

  # Installing from local source archive.
  $ pip install <path to archive>

  # Or from the root directory of the unpacked archive.
  $ pip install .

  Alternate installation options:

  Navigate to the root directory of the unpacked archive and
  run one of the following shell commands:

  Install to the global site-packages directory.
  $ python setup.py install

  Install to the user site-packages directory.
  $ python setup.py install --user

  Install to a chosen directory.
  $ python setup.py install --home=<directory>


  Note: The last two installation options may require modification of
  Python's search path (i.e., 'sys.path') or updating an OS environment
  variable.  For example, installing to the user site-packages directory might
  result in the installation of scripts to '~/.local/bin'.  The user may
  then be required to update his $PATH variable:
  $ export PATH=$PATH:~/.local/bin
"""

from setuptools import setup
from setuptools import find_packages


with open('README.rst') as file_object:
  long_description = file_object.read()

setup(
  name = 'securesystemslib',
  version = '0.18.0',
  description = 'A library that provides cryptographic and general-purpose'
      ' routines for Secure Systems Lab projects at NYU',
  license = 'MIT',
  long_description = long_description,
  long_description_content_type = 'text/x-rst',
  author = 'https://www.updateframework.com',
  author_email = 'theupdateframework@googlegroups.com',
  url = 'https://github.com/secure-systems-lab/securesystemslib',
  keywords = 'cryptography, keys, signatures, rsa, ed25519, ecdsa',
  classifiers = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Natural Language :: English',
    'Operating System :: POSIX',
    'Operating System :: POSIX :: Linux',
    'Operating System :: MacOS :: MacOS X',
    'Operating System :: Microsoft :: Windows',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: Implementation :: CPython',
    'Topic :: Security',
    'Topic :: Software Development'
  ],
  project_urls = {
    'Source': 'https://github.com/secure-systems-lab/securesystemslib',
    'Issues': 'https://github.com/secure-systems-lab/securesystemslib/issues',
  },
  python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, <4",
  install_requires = ['six>=1.11.0', 'subprocess32; python_version < "3"'],
  extras_require = {
      'colors': ['colorama>=0.3.9'],
      'crypto:python_version < "3"': ['cryptography>=3.3.2,<3.5'],
      'crypto:python_version >= "3"': ['cryptography>=3.3.2'],
      'pynacl': ['pynacl>1.2.0']},
  tests_require = 'mock; python_version < "3.3"',
  packages = find_packages(exclude=['tests', 'debian']),
  scripts = []
)
