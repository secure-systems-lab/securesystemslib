#!/usr/bin/env python

"""
<Program Name>
  aggregate_tests.py

<Author>
  Konstantin Andrianov.
  Zane Fisher.

<Started>
  January 26, 2013.

  August 2013.
  Modified previous behavior that explicitly imported individual
  unit tests. -Zane Fisher

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Run all the unit tests from every .py file beginning with "test_" in
  'securesystemslib/tests'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys
import unittest

if __name__ == '__main__':
  suite = unittest.TestLoader().discover("tests", top_level_dir=".")
  all_tests_passed = unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful()
  if not all_tests_passed:
    sys.exit(1)
