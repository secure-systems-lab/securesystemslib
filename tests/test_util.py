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

import os
import sys
import shutil
import logging
import tempfile
import unittest
import timeit

import securesystemslib.settings
import securesystemslib.hash
import securesystemslib.util
import securesystemslib.unittest_toolbox as unittest_toolbox
import securesystemslib.exceptions as exceptions

logger = logging.getLogger(__name__)


class TestUtil(unittest_toolbox.Modified_TestCase):

  def setUp(self):
    unittest_toolbox.Modified_TestCase.setUp(self)
    self.temp_fileobj = tempfile.TemporaryFile()


  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)
    self.temp_fileobj.close()



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
      if isinstance(bogus_input, str):
        self.assertRaises(securesystemslib.exceptions.StorageError,
            securesystemslib.util.get_file_details, bogus_input)
      else:
        self.assertRaises(securesystemslib.exceptions.FormatError,
            securesystemslib.util.get_file_details, bogus_input)



  def test_B2_get_file_hashes(self):
    # Goal: Verify proper output given certain expected/unexpected input.

    # Making a temporary file.
    filepath = self.make_temp_data_file()

    # Computing the hash of the tempfile.
    digest_object = securesystemslib.hash.digest_filename(filepath, algorithm='sha256')
    file_hash = {'sha256' : digest_object.hexdigest()}

    # Test: Expected input.
    self.assertEqual(securesystemslib.util.get_file_hashes(filepath),
        file_hash)

    # Test: Incorrect input.
    bogus_inputs = [self.random_string(), 1234, [self.random_string()],
        {'a': 'b'}, None]

    for bogus_input in bogus_inputs:
      if isinstance(bogus_input, str):
        self.assertRaises(securesystemslib.exceptions.StorageError,
            securesystemslib.util.get_file_hashes, bogus_input)
      else:
        self.assertRaises(securesystemslib.exceptions.FormatError,
            securesystemslib.util.get_file_hashes, bogus_input)



  def test_B3_get_file_length(self):
    # Goal: Verify proper output given certain expected/unexpected input.

    # Making a temporary file.
    filepath = self.make_temp_data_file()

    # Computing the length of the tempfile.
    digest_object = securesystemslib.hash.digest_filename(filepath, algorithm='sha256')
    file_length = os.path.getsize(filepath)

    # Test: Expected input.
    self.assertEqual(securesystemslib.util.get_file_length(filepath), file_length)

    # Test: Incorrect input.
    bogus_inputs = [self.random_string(), 1234, [self.random_string()],
        {'a': 'b'}, None]

    for bogus_input in bogus_inputs:
      if isinstance(bogus_input, str):
        self.assertRaises(securesystemslib.exceptions.StorageError,
            securesystemslib.util.get_file_length, bogus_input)
      else:
        self.assertRaises(securesystemslib.exceptions.FormatError,
            securesystemslib.util.get_file_length, bogus_input)



  def  test_B4_ensure_parent_dir(self):
    existing_parent_dir = self.make_temp_directory()
    non_existing_parent_dir = os.path.join(existing_parent_dir, 'a', 'b')

    for parent_dir in [existing_parent_dir, non_existing_parent_dir, 12, [3]]:
      if isinstance(parent_dir, str):
        securesystemslib.util.ensure_parent_dir(os.path.join(parent_dir, 'a.txt'))
        self.assertTrue(os.path.isdir(parent_dir))

      else:
        self.assertRaises(securesystemslib.exceptions.FormatError,
            securesystemslib.util.ensure_parent_dir, parent_dir)

    # Check that when a folder cannot be created a StorageError is thrown
    with self.assertRaises(securesystemslib.exceptions.StorageError):
      securesystemslib.util.ensure_parent_dir("/a/file.txt")

    # When we call ensure_parent_dir with filepath arg like "a.txt",
    # then the directory of that filepath will be an empty string.
    # We want to make sure that securesyslib.storage.create_folder()
    # won't be called with an empty string and thus raise an exception.
    # If an exception is thrown the test will fail.
    securesystemslib.util.ensure_parent_dir('a.txt')



  def  test_B5_file_in_confined_directories(self):
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



  def  test_B7_load_json_string(self):
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



  def  test_B8_load_json_file(self):
    data = ['a', {'b': ['c', None, 30.3, 29]}]
    filepath = self.make_temp_file()
    fileobj = open(filepath, 'wt')
    securesystemslib.util.json.dump(data, fileobj)
    fileobj.close()
    self.assertEqual(data, securesystemslib.util.load_json_file(filepath))

    # Improperly formatted arguments.
    for bogus_arg in [1, [b'a'], {'a':b'b'}]:
      self.assertRaises(securesystemslib.exceptions.FormatError,
          securesystemslib.util.load_json_file, bogus_arg)

    # Non-existent path.
    self.assertRaises(securesystemslib.exceptions.StorageError,
        securesystemslib.util.load_json_file, 'non-existent.json')

    # Invalid JSON content.
    filepath_bad_data = self.make_temp_file()
    fileobj = open(filepath_bad_data, 'wt')
    fileobj.write('junk data')
    fileobj.close()

    self.assertRaises(securesystemslib.exceptions.Error,
      securesystemslib.util.load_json_file, filepath_bad_data)



  def test_B9_persist_temp_file(self):
    # Destination directory to save the temporary file in.
    dest_temp_dir = self.make_temp_directory()

    # Test the default of persisting the file and closing the tmpfile
    dest_path = os.path.join(dest_temp_dir, self.random_string())
    tmpfile = tempfile.TemporaryFile()
    tmpfile.write(self.random_string().encode('utf-8'))
    securesystemslib.util.persist_temp_file(tmpfile, dest_path)
    self.assertTrue(dest_path)
    self.assertTrue(tmpfile.closed)

    # Test persisting a file without automatically closing the tmpfile
    dest_path2 = os.path.join(dest_temp_dir, self.random_string())
    tmpfile = tempfile.TemporaryFile()
    tmpfile.write(self.random_string().encode('utf-8'))
    securesystemslib.util.persist_temp_file(tmpfile, dest_path2,
        should_close=False)
    self.assertFalse(tmpfile.closed)

    # Test persisting a file with an empty filename
    with self.assertRaises(exceptions.StorageError):
      securesystemslib.util.persist_temp_file(tmpfile, "")

    tmpfile.close()


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
