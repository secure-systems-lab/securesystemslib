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
import glob
import random
import sys

PYTHON_VERSION_INFO = sys.version_info

# This skip_list contains name of the tests that should not be carried out on
# specific python versions. It is a dictionary with name of the tests as the
# keys and the value is the list whose elements define the python version
# on which the particular test should not be run. An entry in the list must
# include major version and minor version.
# Skip the test if any such listed constraints don't match the python version
# currently running.
# For eg. The libraries used to communicate with the hardware security tokens
# is only supported in Python > (3,0).
TEST_SKIP_LIST = {
  'test_hsm': [{'major': 2, 'minor': 7}],
  'test_hsm_keys': [{'major': 2, 'minor': 7}]
}

# Consistency check of the TEST_SKIP_LIST
for test_skip in TEST_SKIP_LIST:
  for version_info in TEST_SKIP_LIST[test_skip]:
    # Consistency checks.
    assert 'major' in version_info, 'Empty/illogical constraint'
    for keyword in version_info:
      assert keyword in ['major', 'minor'], 'Unrecognized test constraint'


# Generate a list of pathnames that match a pattern (i.e., that begin with
# 'test_' and end with '.py'.  A shell-style wildcard is used with glob() to
# match desired filenames.  All the tests matching the pattern will be loaded
# and run in a test suite.
test_list = glob.glob('test_*.py')


tests_modules_to_run = []

# Loop over all the tests to check if the particular tests is meant to be run
# on this particular python version
for test in test_list:
  # This variable is checked before adding a test to list test_modules_to_run
  is_test_valid = True

  # Remove '.py' from each filename to allow loadTestsFromNames() (called below)
  # to properly load the file as a module.
  assert test[-3:] == '.py', 'aggregate_tests.py is inconsistent; fix.'
  test = test[:-3]

  if test in TEST_SKIP_LIST:
    for test_version_info in TEST_SKIP_LIST[test]:
      if PYTHON_VERSION_INFO.major == test_version_info['major'] \
          and PYTHON_VERSION_INFO.minor == test_version_info['minor']:
        is_test_valid = False
        break
  if is_test_valid:
    tests_modules_to_run.append(test)

# Randomize the order in which the tests run.  Randomization might catch errors
# with unit tests that do not properly clean up or restore monkey-patched
# modules.
random.shuffle(tests_modules_to_run)

if __name__ == '__main__':
  suite = unittest.TestLoader().loadTestsFromNames(tests_modules_to_run)
  all_tests_passed = unittest.TextTestRunner(
      verbosity=1, buffer=True).run(suite).wasSuccessful()
  if not all_tests_passed:
    sys.exit(1)
