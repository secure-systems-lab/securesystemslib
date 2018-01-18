# Changelog

## securesystemslib v0.10.9

* Add `debian` directory (and files) that can be used to package a .deb file.

* Modify functions that generate or import keys so that the key file's path is
  shown if the function prompts for a password.

* Add colorama dependency.  It is used to colorize some of the prompts.

* Update dependencies to their latest version.

* Support KEYID filenames for generated key files.  KEYID filenames are used
  if a filename is not specified.

* Minor edits to comments, indentation, whitespace, etc.

* Modify generate_rsa_key() so that leading and trailing newline characters
  are stripped before generating the KEYID.  This is done so that the
  KEYID generated from imported keys match. Imported PEM keys are
  stripped of any leading and trailing newline characters before the KEYID is
  generated.

## securesystemslib v0.10.8

* Drop support for Python 2.6 and 3.3

* Add support for Python 3.6

* Fix bug in PEM parser. See https://github.com/secure-systems-lab/securesystemslib/issues/54

* Drop PyCrypto and multiple-library support

* Update dependencies

* Verify that the arguments to verify_signature() have matching KEYIDs

* Add a changelog file (this one :)

## securesystemslib v0.10.7
@vladimir-v-diaz vladimir-v-diaz released this on Aug 23 · 79 commits to master since this release

* Implement TAP 9

## securesystemslib v0.10.6
@vladimir-v-diaz vladimir-v-diaz released this on Jul 17 · 127 commits to master since this release

* Fix bug in _get_keyid(), where the hash_algorithm argument to _get_keyid()
was not correctly being used.

## securesystemslib v0.10.5
@vladimir-v-diaz vladimir-v-diaz released this on Jun 14 · 130 commits to master since this release

* Bump cryptography dependency to v1.9.0

* Fix backwards-incompatible change introduced by v1.9.0 of cryptography
(dependency)

## securesystemslib v0.10.4
@vladimir-v-diaz vladimir-v-diaz released this on Jan 23 · 146 commits to master since this release

* Add PUBLIC_KEY_SCHEMA and PUBLIC_KEYVAL_SCHEMA

* Remove ssl_crypto/ssl_commons relics in docstrings

## securesystemslib v0.10.3
@vladimir-v-diaz vladimir-v-diaz released this on Jan 19 · 152 commits to master since this release

* Initial pre-release
