#!/usr/bin/env python

"""
<Program Name>
  test_exceptions.py

<Author>
  Vladimir Diaz

<Started>
  December 20, 2016.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for exceptions.py (mainly the exceptions defined there).
"""

import unittest
import logging

import securesystemslib.exceptions

logger = logging.getLogger(__name__)

class TestExceptions(unittest.TestCase):
  def setUp(self):
    pass


  def tearDown(self):
    pass


  def test_bad_signature_error(self):
    bad_signature_error = securesystemslib.exceptions.BadSignatureError(
        'bad sig')
    logger.error(bad_signature_error)


  def test_bad_hash_error(self):
    bad_hash_error = securesystemslib.exceptions.BadHashError(
        '01234', '56789')
    logger.error(bad_hash_error)


  def test_invalid_metadata_json_error(self):
    format_error = securesystemslib.exceptions.FormatError(
        'Improperly formatted JSON')
    invalid_metadata_json_error = \
        securesystemslib.exceptions.InvalidMetadataJSONError(format_error)
    logger.error(invalid_metadata_json_error)



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
