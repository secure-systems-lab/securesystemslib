#!/usr/bin/env python

"""
<Program Name>
  test_util.py

<Author>
  Konstantin Andrianov.

<Started>
  February 1, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'util.py'
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import sys
import gzip
import shutil
import logging
import tempfile
import unittest
import timeit

import securesystemslib.settings
import securesystemslib.hash
import securesystemslib.util
import securesystemslib.unittest_toolbox as unittest_toolbox

import six

logger = logging.getLogger('securesystemslib_test_util')


class TestUtil(unittest_toolbox.Modified_TestCase):

  def setUp(self):
    unittest_toolbox.Modified_TestCase.setUp(self)
    self.temp_fileobj = securesystemslib.util.TempFile()

		

  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)
    self.temp_fileobj.close_temp_file()



  def test_A1_tempfile_close_temp_file(self):
    # Was the temporary file closed?
    self.temp_fileobj.close_temp_file()
    self.assertTrue(self.temp_fileobj.temporary_file.closed)



  def _extract_tempfile_directory(self, config_temp_dir=None):
    """
      Takes a directory (essentially specified in the settings.py as
      'temporary_directory') and substitutes tempfile.TemporaryFile() with
      tempfile.mkstemp() in order to extract actual directory of the stored
      tempfile.  Returns the config's temporary directory (or default temp
      directory) and actual directory.
    """

    # Patching 'settings.temporary_directory'.
    securesystemslib.settings.temporary_directory = config_temp_dir

    if config_temp_dir is None:
      # 'config_temp_dir' needs to be set to default.
      config_temp_dir = tempfile.gettempdir()

    # Patching 'tempfile.TemporaryFile()' (by substituting
    # temfile.TemporaryFile() with tempfile.mkstemp()) in order to get the
    # directory of the stored tempfile object.
    saved_tempfile_TemporaryFile = securesystemslib.util.tempfile.NamedTemporaryFile
    securesystemslib.util.tempfile.NamedTemporaryFile = tempfile.mkstemp
    _temp_fileobj = securesystemslib.util.TempFile()
    securesystemslib.util.tempfile.NamedTemporaryFile = saved_tempfile_TemporaryFile
    junk, _tempfilepath = _temp_fileobj.temporary_file
    _tempfile_dir = os.path.dirname(_tempfilepath)

    # In the case when 'config_temp_dir' is None or some other discrepancy,
    # '_temp_fileobj' needs to be closed manually since tempfile.mkstemp()
    # was used.
    if os.path.exists(_tempfilepath):
      os.remove(_tempfilepath)

    return config_temp_dir, _tempfile_dir



  def test_A2_tempfile_init(self):
    # Goal: Verify that temporary files are stored in the appropriate temp
    # directory.  The location of the temporary files is set in 'settings.py'.

    # Test: Expected input verification.
    # Assumed 'settings.temporary_directory' is 'None' initially.
    temp_file = securesystemslib.util.TempFile()
    temp_file_directory = os.path.dirname(temp_file.temporary_file.name)
    self.assertEqual(tempfile.gettempdir(), temp_file_directory)

    saved_temporary_directory = securesystemslib.settings.temporary_directory
    temp_directory = self.make_temp_directory()
    securesystemslib.settings.temporary_directory = temp_directory
    temp_file = securesystemslib.util.TempFile()
    temp_file_directory = os.path.dirname(temp_file.temporary_file.name)
    self.assertEqual(temp_directory, temp_file_directory)

    securesystemslib.settings.temporary_directory = saved_temporary_directory

    # Test: Unexpected input handling.
    config_temp_dirs = [self.random_string(), 123, ['a'], {'a':1}]
    for config_temp_dir in config_temp_dirs:
      config_temp_dir, actual_dir = \
      self._extract_tempfile_directory(config_temp_dir)
      self.assertEqual(tempfile.gettempdir(), actual_dir)



  def test_A3_tempfile_read(self):
    filepath = self.make_temp_data_file(data = '1234567890')
    fileobj = open(filepath, 'rb')

    # Patching 'temp_fileobj.temporary_file'.
    self.temp_fileobj.temporary_file = fileobj

    # Test: Expected input.
    self.assertEqual(self.temp_fileobj.read().decode('utf-8'), '1234567890')
    self.assertEqual(self.temp_fileobj.read(4).decode('utf-8'), '1234')

    # Test: Unexpected input.
    for bogus_arg in ['abcd', ['abcd'], {'a':'a'}, -100]:
      self.assertRaises(securesystemslib.exceptions.FormatError,
          self.temp_fileobj.read, bogus_arg)



  def test_A4_tempfile_write(self):
    data = self.random_string()
    self.temp_fileobj.write(data.encode('utf-8'))
    self.assertEqual(data, self.temp_fileobj.read().decode('utf-8'))

    self.temp_fileobj.write(data.encode('utf-8'), auto_flush=False)
    self.assertEqual(data, self.temp_fileobj.read().decode('utf-8'))



  def test_A5_tempfile_move(self):
    # Destination directory to save the temporary file in.
    dest_temp_dir = self.make_temp_directory()
    dest_path = os.path.join(dest_temp_dir, self.random_string())
    self.temp_fileobj.write(self.random_string().encode('utf-8'))
    self.temp_fileobj.move(dest_path)
    self.assertTrue(dest_path)



  def _compress_existing_file(self, filepath):
    """
    [Helper]Compresses file 'filepath' and returns file path of
    the compresses file.
    """

    # NOTE: DO NOT forget to remove the newly created compressed file!
    if os.path.exists(filepath):
      compressed_filepath = filepath+'.gz'
      f_in = open(filepath, 'rb')
      f_out = gzip.open(compressed_filepath, 'wb')
      f_out.writelines(f_in)
      f_out.close()
      f_in.close()

      return compressed_filepath

    else:
      logger.error('Compression of ' + repr(filepath)  +' failed.'
          '  Path does not exist.')
      sys.exit(1)



  def _decompress_file(self, compressed_filepath):
    """[Helper]"""
    if os.path.exists(compressed_filepath):
      f = gzip.open(compressed_filepath, 'rb')
      file_content = f.read()
      f.close()
      return file_content

    else:
      logger.error('Decompression of ' + repr(compressed_filepath) + ' failed.'
          '  Path does not exist.')
      sys.exit(1)



  def test_A6_tempfile_decompress_temp_file_object(self):
    # Setup: generate a temp file (self.make_temp_data_file()),
    # compress it.  Write it to self.temp_fileobj().
    filepath = self.make_temp_data_file()
    fileobj = open(filepath, 'rb')
    compressed_filepath = self._compress_existing_file(filepath)
    compressed_fileobj = open(compressed_filepath, 'rb')
    self.temp_fileobj.write(compressed_fileobj.read())
    os.remove(compressed_filepath)

    # Try decompression using incorrect compression type i.e. compressions
    # other than 'gzip'.  In short feeding incorrect input.
    bogus_args = ['zip', 1234, self.random_string()]
    for arg in bogus_args:
      self.assertRaises(securesystemslib.exceptions.Error,
          self.temp_fileobj.decompress_temp_file_object, arg)

    # Test for a valid util.decompress_temp_file_object() call.
    self.temp_fileobj.decompress_temp_file_object('gzip')
    self.assertEqual(self.temp_fileobj.read(), fileobj.read())

    # Checking the content of the TempFile's '_orig_file' instance.
    check_compressed_original = self.make_temp_file()
    with open(check_compressed_original, 'wb') as file_object:
      self.temp_fileobj._orig_file.seek(0)
      original_content = self.temp_fileobj._orig_file.read()
      file_object.write(original_content)

    data_in_orig_file = self._decompress_file(check_compressed_original)
    fileobj.seek(0)
    self.assertEqual(data_in_orig_file, fileobj.read())

    # Try decompressing once more.
    self.assertRaises(securesystemslib.exceptions.Error,
        self.temp_fileobj.decompress_temp_file_object, 'gzip')

    # Test decompression of invalid gzip file.
    temp_file = securesystemslib.util.TempFile()
    temp_file.write(b'bad zip')
    contents = temp_file.read()
    self.assertRaises(securesystemslib.exceptions.DecompressionError,
        temp_file.decompress_temp_file_object, 'gzip')



  def test_B1_get_file_details(self):
    # Goal: Verify proper output given certain expected/unexpected input.

    # Making a temporary file.
    filepath = self.make_temp_data_file()

    # Computing the hash and length of the tempfile.
    digest_object = securesystemslib.hash.digest_filename(filepath, algorithm='sha256')
    file_hash = {'sha256' : digest_object.hexdigest()}
    file_length = os.path.getsize(filepath)

    # Test: Expected input.
    self.assertEqual(securesystemslib.util.get_file_details(filepath),
        (file_length, file_hash))

    # Test: Incorrect input.
    bogus_inputs = [self.random_string(), 1234, [self.random_string()],
        {'a': 'b'}, None]

    for bogus_input in bogus_inputs:
      if isinstance(bogus_input, six.string_types):
        self.assertRaises(securesystemslib.exceptions.Error,
            securesystemslib.util.get_file_details, bogus_input)
      else:
        self.assertRaises(securesystemslib.exceptions.FormatError,
            securesystemslib.util.get_file_details, bogus_input)



  def  test_B2_ensure_parent_dir(self):
    existing_parent_dir = self.make_temp_directory()
    non_existing_parent_dir = os.path.join(existing_parent_dir, 'a', 'b')

    for parent_dir in [existing_parent_dir, non_existing_parent_dir, 12, [3]]:
      if isinstance(parent_dir, six.string_types):
        securesystemslib.util.ensure_parent_dir(os.path.join(parent_dir, 'a.txt'))
        self.assertTrue(os.path.isdir(parent_dir))

      else:
        self.assertRaises(securesystemslib.exceptions.FormatError,
            securesystemslib.util.ensure_parent_dir, parent_dir)



  def  test_B3_file_in_confined_directories(self):
    # Goal: Provide invalid input for 'filepath' and 'confined_directories'.
    # Include inputs like: '[1, 2, "a"]' and such...
    # Reference to 'file_in_confined_directories()' to improve readability.
    in_confined_directory = securesystemslib.util.file_in_confined_directories
    list_of_confined_directories = ['a', 12, {'a':'a'}, [1]]
    list_of_filepaths = [12, ['a'], {'a':'a'}, 'a']
    for bogus_confined_directory in list_of_confined_directories:
      for filepath in list_of_filepaths:
        self.assertRaises(securesystemslib.exceptions.FormatError,
            in_confined_directory, filepath, bogus_confined_directory)

    # Test: Inputs that evaluate to False.
    confined_directories = ['a/b/', 'a/b/c/d/']
    self.assertFalse(in_confined_directory('a/b/c/1.txt', confined_directories))

    confined_directories = ['a/b/c/d/e/']
    self.assertFalse(in_confined_directory('a', confined_directories))
    self.assertFalse(in_confined_directory('a/b', confined_directories))
    self.assertFalse(in_confined_directory('a/b/c', confined_directories))
    self.assertFalse(in_confined_directory('a/b/c/d', confined_directories))
    # Below, 'e' is a file in the 'a/b/c/d/' directory.
    self.assertFalse(in_confined_directory('a/b/c/d/e', confined_directories))

    # Test: Inputs that evaluate to True.
    self.assertTrue(in_confined_directory('a/b/c.txt', ['']))
    self.assertTrue(in_confined_directory('a/b/c.txt', ['a/b/']))
    self.assertTrue(in_confined_directory('a/b/c.txt', ['x', '']))
    self.assertTrue(in_confined_directory('a/b/c/..', ['a/']))


  def test_B4_import_json(self):
    self.assertTrue('json' in sys.modules)
    json_module = securesystemslib.util.import_json()
    self.assertTrue(json_module is not None)

    # Test import_json() when 'util._json_moduel' is non-None.
    securesystemslib.util._json_module = 'junk_module'
    self.assertEqual(securesystemslib.util.import_json(), 'junk_module')



  def  test_B5_load_json_string(self):
    # Test normal case.
    data = ['a', {'b': ['c', None, 30.3, 29]}]
    json_string = securesystemslib.util.json.dumps(data)
    self.assertEqual(data, securesystemslib.util.load_json_string(json_string))

    # Test invalid arguments.
    self.assertRaises(securesystemslib.exceptions.Error,
        securesystemslib.util.load_json_string, 8)
    invalid_json_string = json_string + '.'
    self.assertRaises(securesystemslib.exceptions.Error,
        securesystemslib.util.load_json_string, invalid_json_string)



  def  test_B6_load_json_file(self):
    data = ['a', {'b': ['c', None, 30.3, 29]}]
    filepath = self.make_temp_file()
    fileobj = open(filepath, 'wt')
    securesystemslib.util.json.dump(data, fileobj)
    fileobj.close()
    self.assertEqual(data, securesystemslib.util.load_json_file(filepath))

    # Test a gzipped file.
    compressed_filepath = self._compress_existing_file(filepath)
    self.assertEqual(data,
        securesystemslib.util.load_json_file(compressed_filepath))

    # Improperly formatted arguments.
    for bogus_arg in [1, [b'a'], {'a':b'b'}]:
      self.assertRaises(securesystemslib.exceptions.FormatError,
          securesystemslib.util.load_json_file, bogus_arg)

    # Non-existent path.
    self.assertRaises(IOError,
        securesystemslib.util.load_json_file, 'non-existent.json')

    # Invalid JSON content.
    filepath_bad_data = self.make_temp_file()
    fileobj = open(filepath_bad_data, 'wt')
    fileobj.write('junk data')
    fileobj.close()

    self.assertRaises(securesystemslib.exceptions.Error,
      securesystemslib.util.load_json_file, filepath_bad_data)



  def test_C1_get_target_hash(self):
    # Test normal case.
    expected_target_hashes = {
      '/file1.txt': 'e3a3d89eb3b70ce3fbce6017d7b8c12d4abd5635427a0e8a238f53157df85b3d',
      '/README.txt': '8faee106f1bb69f34aaf1df1e3c2e87d763c4d878cb96b91db13495e32ceb0b0',
      '/warehouse/file2.txt': 'd543a573a2cec67026eff06e75702303559e64e705eba06f65799baaf0424417'
    }
    for filepath, target_hash in six.iteritems(expected_target_hashes):
      self.assertTrue(securesystemslib.formats.RELPATH_SCHEMA.matches(filepath))
      self.assertTrue(securesystemslib.formats.HASH_SCHEMA.matches(target_hash))
      self.assertEqual(securesystemslib.util.get_target_hash(filepath), target_hash)

    # Test for improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.util.get_target_hash, 8)



  def test_C5_unittest_toolbox_make_temp_directory(self):
    # Verify that the tearDown function does not fail when
    # unittest_toolbox.make_temp_directory deletes the generated temp directory
    # here.
    temp_directory = self.make_temp_directory()
    os.rmdir(temp_directory)



  def test_c5_unittest_toolbox_random_path(self):
    # Verify that a random path can be generated with unittest_toolbox.
    random_path = self.random_path(length=10)
    self.assertTrue(securesystemslib.formats.PATH_SCHEMA.matches(random_path))
    self.assertTrue(10, len(random_path))


  def test_c6_get_compressed_length(self):
   self.temp_fileobj.write(b'hello world')
   self.assertTrue(self.temp_fileobj.get_compressed_length() == 11)

   temp_file = securesystemslib.util.TempFile()



  def test_digests_are_equal(self):
    digest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    # Normal case: test for digests that are equal.
    self.assertTrue(securesystemslib.util.digests_are_equal(digest, digest))

    # Normal case: test for digests that are unequal.
    self.assertFalse(securesystemslib.util.digests_are_equal(digest, '0a8df1'))

    # Test for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.util.digests_are_equal, 7, digest)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.util.digests_are_equal, digest, 7)

    # Test that digests_are_equal() takes the same amount of time to compare
    # equal and unequal arguments.
    runtime = timeit.timeit('digests_are_equal("ab8df", "ab8df")',
        setup='from securesystemslib.util import digests_are_equal',
        number=100000)

    runtime2 = timeit.timeit('digests_are_equal("ab8df", "1b8df")',
        setup='from securesystemslib.util import digests_are_equal',
        number=100000)

    runtime3 = timeit.timeit('"ab8df" == "ab8df"', number=100000)

    runtime4 = timeit.timeit('"ab8df" == "1b8df"', number=1000000)

    # The ratio for the 'digest_are_equal' runtimes should be at or near 1.
    ratio_digests_are_equal = abs(runtime2 / runtime)

    # The ratio for the variable-time runtimes should be (>1) & at or near 10?
    ratio_variable_compare = abs(runtime4 / runtime3)

    self.assertTrue(ratio_digests_are_equal < ratio_variable_compare)



# Run unit test.
if __name__ == '__main__':
  unittest.main()
