# Changelog

## securesystemslib v0.19.0

### Added
* Enable setting which GPG client to use through an environment variable (#315)

### Changed
* Dropped support for EOL Python 3.5 and add support for Python 3.9 (#314)
* Converted the default local storage backend, FilesystemBackend, to be a
  singleton (#302)
* Migrated CI from travis-ci.org to travis-ci.com (#303) then later to GitHub
  Actions (#324)
* Bump dependencies: cffi (#306, #329), cryptography (#322, #333). NOTE: the
  latest version of cryptography is no longer used on Python 2, as that is not
  supported.
* Updated Debian packaging metadata (#313 & #318)
* Improved messaging for issues automatically filed on upstream changes to our
  vendored ed25519 dependency (#317)
* Updated the ed25519 tracking script for upstream's branch name change (#331)

### Fixed
* Empty lists should not be used as the default argument for a function (#304)

## securesystemslib v0.18.0

### Added
* `interface.generate_and_write_unencrypted_{rsa,ed25519,ecdsa}_keypair` (#288)
* `interface.generate_and_write_{rsa,ed25519,ecdsa}_keypair_with_prompt` (#288)
* `interface.import_privatekey_from_file`(#288)
* GitHub Action to auto-check upstream changes for vendored ed25519 (#294)

### Changed
* `interface.generate_and_write_{rsa,ed25519,ecdsa}_keypair` require a password
  as first positional argument (#288)
* `interface.import_{rsa,ed25519,ecdsa}_privatekey_from_file` do not error on
  empty password, but pass it on to lower level decryption routines (#288)
* `interface.import_ecdsa_privatekey_from_file` supports loading unencrypted
  private keys (#288)
* Revise `interface` and `gpg.functions` docstrings, and example snippets, and
  use Sphinx compatible Google Style docstring format (#288, #300)
* Linter-flagged cosmetic changes (#292, #295, #296)
* Bump dependencies: cryptography (#291, #293)
* Bump vendor copy of ed25519 (#299)

## securesystemslib v0.17.0

### Added
* Add `interface.import_publickeys_from_file()` convenience function (#278, #285)
* Add `gpg.export_pubkeys()` convenience function (#277)
* Add support to `hash` module for blake2b-256 algorithm (#283)

### Changed
* Use ecdsa as keytype for ECDSA keys to better distinguish between keytype
  and scheme (#267)
* Bump dependencies: cffi (#266, #273), cryptography (#269, #274),
  and colorama (#284)
* Removed python-dateutil dependency (#268)
* Prepare Debian downstream releases (#198)
* Remove unused helper (`_prompt`) and global (`SUPPORTED_KEY_TYPES`) from
  interface module (#276)
* Refactored and extended interface tests (#279, #287)

## securesystemslib v0.16.0

### Added
* Added new, self-explanatory, AnyNonEmptyString schema (#244)
* Separate functions for getting a file's length, `util.get_file_length()`, and
  a file's hashes, `util.get_file_hashes()`  (#259)

### Changed
* Improved documentation for abstract storage interface (#240)
* Change PATHS_SCHEMA to be any non-empty string (#244)
* Updated `keys.format_metadata_to_key()` to take an optional list of hashing
  algorithms rather than requiring users modify `settings.HASH_ALGORITHMS` to
  change this behaviour (#227)
* Rather than silently ignoring empty paths, throw an exception on empty file
  path in `storage.FileSystemBackend.create_folder` (#252)

### Fixed
* Proper tearing down of storage tests (#249)
* Handle empty directories in `util.ensure_parent_dir()` (#260)
* Fix tests to work with newer versions (3.0 or newer) of the cryptography
  module (#264)

## securesystemslib v0.15.0

* Allow Blake (blake2s and blake2b) hashing algorithms (#218)
* *new features*
  * Add nistp384 signature verification support (#228)
  * Allow callers to provide a default keyid in format_metadata_to_key, rather
    than using the default keyid value of a hash of the canonical JSON of the
	key metadata (#225)
  * Implement files and directories abstraction as an abstract base class;
    StorageBackendInterface, with a concrete implementation for local
	filesystems; FilesystemBackend  (#232). This enables users, such as tuf,
	to support non-local/non-traditional filesystems, so long as they provide
	an object implementing securesystemslib.storage.StorageBackendInterface.
	All functions which take a StorageBackendInterface default to creating a
	FilesystemBackend object for local filesystem interaction when an object
	isn't provided. This means that behaviour remains the same as in prior
	(0.14.x) releases of securesystemslib, only instead of throwing exceptions
	from the Python standard library a custom, generic, error is thrown:
	securesystemslib.exceptions.StorageError
* *removed features*
  * Remove support for gzipped files in load_json_file (#230)

## securesystemslib v0.14.2

* Re-enable OpenPGP signature verification without GnuPG (#215)

## securesystemslib v0.14.1

* Improve logging (#212, #211)
* Fix dependency monitoring and revise requirements files (#209)
* Further improve optional dependency handling (#206)
* Update release metadata (#205)

## securesystemslib v0.14.0

* *behavior change*
  * Default to pure Python ed25519 signature verification when nacl is unavailable (#200)
  * Fix settings.SUBPROCESS_TIMEOUT access in process module (#202)
* Improve schema-related error message (#199)
* Generally improve optional dependency handling (#200)
* Enhance test configuration, fix typos and remove unused code (#201)
* Fix improper identity check (#203)

## securesystemslib v0.13.1

* Fix MANIFEST.in to include all test data in source release (#196)

## securesystemslib v0.13.0

* Add support for *OpenPGP* EdDSA/ed25519 keys and signatures (#188)
bump
## securesystemslib v0.12.2

* Remove unnecessary `python-dateutil==2.8.0` version pinning to not cause
  downstream dependency conflicts (#192)

## securesystemslib v0.12.1

* Fix stream duplication race conditions in subprocess interface (#186)

## securesystemslib v0.12.0

* *backwards incompatible*
  * Remove data serialization in `create_signature` and `verify_signature` (#162)
  * Replace mostly obsolete `TempFile` utility with single helper function (#181)
  * Remove *TUF*-specific code and comments (#165)
* *new features*
  * Add support for *pkcs1v15* RSA signature scheme and additional hash algorithms (#173, #175)
  * Add basic *OpenPGP* support, transferred from [in-toto](https://github.com/in-toto/in-toto) (#174, #176, #185)
* *miscellaneous*
  * Fix publishing of code coverage  and enhance test configuration (#171)
  * Make colorama a strict dependency (#178)
  * Enhance source distribution metadata (#168)
  * Update downstream Debian metadata (#177)

## securesystemslib v0.11.3

* Provide option to normalize line endings (`\r\n` -> `\n`, `\r` -> `\n`) when
calculating the hash of a file (default: do not normalize).
* Update developer dependencies (dev-requirements.txt):
  * cryptography 2.2.2 to 2.3.1
  * tox 3.0.0 to 3.2.1

## securesystemslib v0.11.2

* No (en|de)cryption of ed25519 key files when given empty password (pr #148).

* Support ed25519 crypto in pure python with default installation (pr #149).

* Update installation instructions to indicate commands needed to install
  optional dependencies for RSA and ECDSA support (pr #150).

* Edit setup.py's license classifier to `OSI LIcense :: MIT` (pr #151).

## securesystemslib v0.11.1

* Convert `\r\n` newline characters to `\n`, so that the same KEYID is
  generated for key data regardless of the newline style used (pr #146).

## securesystemslib v0.11.0

* Add `prompt` parameter to interface.import_rsa_privatekey_from_file() (pr #124).

* Update dependencies

## securesystemslib v0.10.11

* Replace deprecated `cryptography` methods.  signer() and verifier()
  should be replaced with sign() and verify(), respectively.

* Update dependencies.

## securesystemslib v0.10.10

* Add get_password() to API.

* Enable password confirmation in all `generate_and_write_XXX_keypair()`
  functions.

* Minor:
  Fix broken link in comment (recommended # of bits for RSA keys).
  Add `TEXT_SCHEMA`.
  Remove obsolete function (check_crypto_libaries) from `.coveragerc`.

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
