"""
<Program Name>
  check_gpg_available.py

<Author>
  Zack Newman <zjn@chainguard.dev>

<Started>
  September 30, 2022.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The test suite passes even if GPG is not available, because GPG-dependent
  tests are skipped if GPG is not present.

  This file asserts the availability of GPG, so CI environments that expect GPG
  will notice if it goes away unexpectedly rather than silently skipping the GPG
  tests.

  NOTE: the filename is purposefully check_ rather than test_ so that test
  discovery doesn't find this unittest and the tests within are only run
  when explicitly invoked.
"""

import unittest

import securesystemslib.gpg.constants


class TestGpgAvailable(unittest.TestCase):
    """Test that securesystemslib finds some GPG executable in the environment."""

    def test_gpg_available(self):
        """Test that GPG is available."""
        self.assertTrue(securesystemslib.gpg.constants.have_gpg())


if __name__ == "__main__":
    unittest.main(verbosity=1, buffer=True)
