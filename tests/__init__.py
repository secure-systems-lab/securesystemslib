"""Securesystemslib tests.

NOTE: This file is only considered when running tests via aggregate_tests.py, or
with the '-m' flag, when invoked individually.

"""

# Increase gpg subprocess timeout -- Windows CI fails frequently with default 10s.
import securesystemslib._gpg.constants

securesystemslib._gpg.constants.GPG_TIMEOUT = 120
