#!/usr/bin/env python

"""
<Program Name>
  test_hash.py

<Authors>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  Refactored March 1, 2012 (VLAD).  Based on a previous version of this module.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'hash.py'.
"""

import io
import os
import logging
import sys
import tempfile
import unittest

import securesystemslib.exceptions
import securesystemslib.hash

logger = logging.getLogger(__name__)


if not 'hashlib' in securesystemslib.hash.SUPPORTED_LIBRARIES:
  logger.warning('Not testing hashlib: could not be imported.')


class TestHash(unittest.TestCase):

  @staticmethod
  def _is_supported_combination(library, algorithm):
    blake_algos = ['blake2b', 'blake2b-256', 'blake2s']

    # pyca does not support blake2*
    if algorithm in blake_algos:
      if library == 'pyca_crypto':
        return False
    return True


  def _run_with_all_algos_and_libs(self, test_func):
    algorithms = [
      'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
      'blake2b-256', 'blake2b', 'blake2s',
    ]
    for algorithm in algorithms:
      self._run_with_all_hash_libraries(test_func, algorithm)


  def _run_with_all_hash_libraries(self, test_func, algorithm):
    for lib in securesystemslib.hash.SUPPORTED_LIBRARIES:
      if self._is_supported_combination(lib, algorithm):
        test_func(lib, algorithm)
      else:
        self.assertRaises(
            securesystemslib.exceptions.UnsupportedAlgorithmError,
            test_func, lib, algorithm)


  def _do_algorithm_update(self, library, algorithm):
    expected = {
      'blake2b': [
        '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
        '333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c',
        'e1161a4e6e6ed9da6928b5e96c24d5b957018f997994f16c05497af059d4f32bb80b34f478aa1fc173f6e45d859958c891e53c2c0bf8eda7c6d3917263641b46',
        'e1161a4e6e6ed9da6928b5e96c24d5b957018f997994f16c05497af059d4f32bb80b34f478aa1fc173f6e45d859958c891e53c2c0bf8eda7c6d3917263641b46',
      ],
      'blake2b-256': [
        '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8',
        '8928aae63c84d87ea098564d1e03ad813f107add474e56aedd286349c0c03ea4',
        '92af150df67e34827f3c13239c4d11cad6f488b447f72e844c10fce6c651e9f0',
        '92af150df67e34827f3c13239c4d11cad6f488b447f72e844c10fce6c651e9f0',
      ],
      'blake2s': [
        '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9',
        '4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90',
        '2b68156e70f71280f7ad021f74620446ee49613a7ed34f5220da7b1dbae9adb2',
        '2b68156e70f71280f7ad021f74620446ee49613a7ed34f5220da7b1dbae9adb2',
      ],
      'md5': [
        'd41d8cd98f00b204e9800998ecf8427e',
        '0cc175b9c0f1b6a831c399e269772661',
        'f034e93091235adbb5d2781908e2b313',
        'f034e93091235adbb5d2781908e2b313',
      ],
      'sha1': [
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        '86f7e437faa5a7fce15d1ddcb9eaeaea377667b8',
        'd7bfa42fc62b697bf6cf1cda9af1fb7f40a27817',
        'd7bfa42fc62b697bf6cf1cda9af1fb7f40a27817',
      ],
      'sha224': [
        'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
        'abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5',
        'ab1342f31c2a6f242d9a3cefb503fb49465c95eb255c16ad791d688c',
        'ab1342f31c2a6f242d9a3cefb503fb49465c95eb255c16ad791d688c',
      ],
      'sha256': [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
        '01d162a5c95d4698c0a3e766ae80d85994b549b877ed275803725f43dadc83bd',
        '01d162a5c95d4698c0a3e766ae80d85994b549b877ed275803725f43dadc83bd',
      ],
      'sha384': [
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
        '54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31',
        'f2c1438e9cc1d24bebbf3b88e60adc169db0c5c459d02054ec131438bf20ebee5ca88c17cb5f1a824fcccf8d2b20b0a9',
        'f2c1438e9cc1d24bebbf3b88e60adc169db0c5c459d02054ec131438bf20ebee5ca88c17cb5f1a824fcccf8d2b20b0a9',
      ],
      'sha512': [
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        '1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75',
        '09ade82ae3c5d54f8375f348563a372106488adef16a74b63b5591849f740bff55ceab22e117b4b09349b860f8a644adb32a9ea542abdecb80bf625160604251',
        '09ade82ae3c5d54f8375f348563a372106488adef16a74b63b5591849f740bff55ceab22e117b4b09349b860f8a644adb32a9ea542abdecb80bf625160604251',
      ],
    }
    digest_object = securesystemslib.hash.digest(algorithm, library)
    
    self.assertEqual(digest_object.hexdigest(), expected[algorithm][0])
    digest_object.update('a'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(), expected[algorithm][1])
    digest_object.update('bbb'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(), expected[algorithm][2])
    digest_object.update(''.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(), expected[algorithm][3])


  def test_blake2s_update(self):
    self._run_with_all_hash_libraries(self._do_algorithm_update, 'blake2s')


  def test_blake2b_update(self):
    self._run_with_all_hash_libraries(self._do_algorithm_update, 'blake2b')


  def test_blake2b_256_update(self):
    self._run_with_all_hash_libraries(self._do_algorithm_update, 'blake2b-256')


  def test_md5_update(self):
    self._run_with_all_hash_libraries(self._do_algorithm_update, 'md5')


  def test_sha1_update(self):
    self._run_with_all_hash_libraries(self._do_algorithm_update, 'sha1')


  def test_sha224_update(self):
    self._run_with_all_hash_libraries(self._do_algorithm_update, 'sha224')


  def test_sha256_update(self):
    self._run_with_all_hash_libraries(self._do_algorithm_update, 'sha256')


  def test_sha384_update(self):
    self._run_with_all_hash_libraries(self._do_algorithm_update, 'sha384')


  def test_sha512_update(self):
    self._run_with_all_hash_libraries(self._do_algorithm_update, 'sha512')


  def test_unsupported_algorithm(self):
    self._run_with_all_hash_libraries(self._do_unsupported_algorithm, 'bogus')


  def _do_unsupported_algorithm(self, library, algorithm):
    self.assertRaises(securesystemslib.exceptions.UnsupportedAlgorithmError,
        securesystemslib.hash.digest, algorithm, library)


  def test_digest_size(self):
    self._run_with_all_algos_and_libs(self._do_digest_size)


  def _do_digest_size(self, library, algorithm):
    digest_sizes = {
      'md5': 16,
      'sha1': 20,
      'sha224': 28,
      'sha256': 32,
      'sha384': 48,
      'sha512': 64,
      'blake2b-256': 32,
      'blake2b': 64,
      'blake2s': 32,
    }
    self.assertEqual(digest_sizes[algorithm],
        securesystemslib.hash.digest(algorithm, library).digest_size)


  def test_update_filename(self):
    self._run_with_all_algos_and_libs(self._do_update_filename)


  def _do_update_filename(self, library, algorithm):
    data = 'abcdefgh' * 4096
    fd, filename = tempfile.mkstemp()
    try:
      os.write(fd, data.encode('utf-8'))
      os.close(fd)
      digest_object_truth = securesystemslib.hash.digest(algorithm, library)
      digest_object_truth.update(data.encode('utf-8'))
      digest_object = securesystemslib.hash.digest_filename(filename,
          algorithm, library)
      self.assertEqual(digest_object_truth.digest(), digest_object.digest())

    finally:
        os.remove(filename)


  def test_update_filename_normalize(self):
    self._run_with_all_algos_and_libs(self._do_update_filename_normalize)


  def _do_update_filename_normalize(self, library, algorithm):
    data = b'ab\r\nd\nf\r' * 4096
    normalized_data = data.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    fd, filename = tempfile.mkstemp()
    try:
      os.write(fd, data)
      os.close(fd)
      digest_object_truth = securesystemslib.hash.digest(algorithm, library)
      digest_object_truth.update(normalized_data)
      digest_object = securesystemslib.hash.digest_filename(filename,
          algorithm, library, normalize_line_endings=True)
      self.assertEqual(digest_object_truth.digest(), digest_object.digest())

    finally:
      os.remove(filename)


  def test_update_file_obj(self):
    self._run_with_all_algos_and_libs(self._do_update_file_obj)


  def _do_update_file_obj(self, library, algorithm):
    data = 'abcdefgh' * 4096
    file_obj = io.StringIO()
    file_obj.write(data)
    digest_object_truth = securesystemslib.hash.digest(algorithm, library)
    digest_object_truth.update(data.encode('utf-8'))
    digest_object = securesystemslib.hash.digest_fileobject(file_obj,
        algorithm, library)

    # Note: we don't seek because the update_file_obj call is supposed
    # to always seek to the beginning.
    self.assertEqual(digest_object_truth.digest(), digest_object.digest())


  def test_digest_from_rsa_scheme(self):
    self._run_with_all_hash_libraries(self._do_get_digest_from_rsa_valid_schemes, 'sha256')
    self._run_with_all_hash_libraries(self._do_get_digest_from_rsa_non_valid_schemes, 'sha256')


  def _do_get_digest_from_rsa_valid_schemes(self, library, algorithm):
    scheme = 'rsassa-pss-sha256'
    expected_digest_cls = type(securesystemslib.hash.digest(algorithm, library))

    self.assertIsInstance(securesystemslib.hash.digest_from_rsa_scheme(scheme, library),
      expected_digest_cls)

  def _do_get_digest_from_rsa_non_valid_schemes(self, library, algorithm):
    self.assertRaises(securesystemslib.exceptions.FormatError,
      securesystemslib.hash.digest_from_rsa_scheme, 'rsassa-pss-sha123', library)



  def test_unsupported_digest_algorithm_and_library(self):
    self.assertRaises(securesystemslib.exceptions.UnsupportedAlgorithmError,
        securesystemslib.hash.digest, 'sha123', 'hashlib')
    self.assertRaises(securesystemslib.exceptions.UnsupportedLibraryError,
        securesystemslib.hash.digest, 'sha256', 'badlib')


# Run unit test.
if __name__ == '__main__':
  unittest.main()
