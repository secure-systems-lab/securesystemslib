#!/usr/bin/env python

"""
<Program Name>
  test_hsm.py

<Author>
  Tansihq Jasoria

<Purpose>
  Test cases for hsm.py module
"""


# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals


import unittest
import logging

import os
import shutil
import six

import securesystemslib.exceptions
import securesystemslib.formats

# To initialize SoftHSM for testing purposes!
if not six.PY2:
  import PyKCS11
  import securesystemslib.hsm
# Library to interact with SoftHSM.
PKCS11LIB = '/usr/local/lib/softhsm/libsofthsm2.so'

# Path where SoftHSM is created and stored
TOKENS_PATH = '/var/lib/softhsm/tokens'

logger = logging.getLogger(__name__)

# Credentials fo the HSM initialization
_USER_PIN = '123456'
_SO_PIN = '654321'
_HSM_LABEL = 'TEST HSM SSL'

KEY_LABEL = 'Test Keys'




@unittest.skipIf(six.PY2, "HSM functionality not supported on Python 2")
class TestHSM(unittest.TestCase):


  @classmethod
  def setUpClass(cls):
    pass


  @classmethod
  def tearDownClass(cls):
    pass


  @classmethod
  def setUp(self):
    pass


  @classmethod
  def tearDown(self):
    pass





# Run the unit tests.
if __name__ == '__main__':
  unittest.main()

