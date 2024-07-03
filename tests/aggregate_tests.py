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

import sys
import unittest

if __name__ == "__main__":
    suite = unittest.TestLoader().discover("tests", top_level_dir=".")
    all_tests_passed = (
        unittest.TextTestRunner(verbosity=1, buffer=True).run(suite).wasSuccessful()
    )
    if not all_tests_passed:
        sys.exit(1)
