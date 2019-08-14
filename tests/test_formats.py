#!/usr/bin/env python

"""
<Program Name>
  test_formats.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 2017 (modified from TUF's original formats.py)

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'formats.py'
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import datetime

import securesystemslib.formats
import securesystemslib.schema

import six


class TestFormats(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    pass



  def test_schemas(self):
    # Test conditions for valid schemas.
    valid_schemas = {
      'ISO8601_DATETIME_SCHEMA': (securesystemslib.formats.ISO8601_DATETIME_SCHEMA,
          '1985-10-21T13:20:00Z'),

      'UNIX_TIMESTAMP_SCHEMA': (securesystemslib.formats.UNIX_TIMESTAMP_SCHEMA,
          499137720),

      'HASH_SCHEMA': (securesystemslib.formats.HASH_SCHEMA, 'A4582BCF323BCEF'),

      'HASHDICT_SCHEMA': (securesystemslib.formats.HASHDICT_SCHEMA,
          {'sha256': 'A4582BCF323BCEF'}),

      'HEX_SCHEMA': (securesystemslib.formats.HEX_SCHEMA, 'A4582BCF323BCEF'),

      'KEYID_SCHEMA': (securesystemslib.formats.KEYID_SCHEMA, '123456789abcdef'),

      'KEYIDS_SCHEMA': (securesystemslib.formats.KEYIDS_SCHEMA,
          ['123456789abcdef', '123456789abcdef']),

      'SCHEME_SCHEMA': (securesystemslib.formats.SCHEME_SCHEMA,
          'ecdsa-sha2-nistp256'),

      'RELPATH_SCHEMA': (securesystemslib.formats.RELPATH_SCHEMA,
          'metadata/root/'),

      'RELPATHS_SCHEMA': (securesystemslib.formats.RELPATHS_SCHEMA,
          ['targets/role1/', 'targets/role2/']),

      'PATH_SCHEMA': (securesystemslib.formats.PATH_SCHEMA,
          '/home/someuser/'),

      'PATHS_SCHEMA': (securesystemslib.formats.PATHS_SCHEMA,
          ['/home/McFly/', '/home/Tannen/']),

      'URL_SCHEMA': (securesystemslib.formats.URL_SCHEMA,
          'https://www.updateframework.com/'),

      'VERSION_SCHEMA': (securesystemslib.formats.VERSION_SCHEMA,
          {'major': 1, 'minor': 0, 'fix': 8}),

      'LENGTH_SCHEMA': (securesystemslib.formats.LENGTH_SCHEMA, 8),

      'NAME_SCHEMA': (securesystemslib.formats.NAME_SCHEMA, 'Marty McFly'),

      'TEXT_SCHEMA': (securesystemslib.formats.TEXT_SCHEMA, 'Password: '),

      'BOOLEAN_SCHEMA': (securesystemslib.formats.BOOLEAN_SCHEMA, True),

      'THRESHOLD_SCHEMA': (securesystemslib.formats.THRESHOLD_SCHEMA, 1),

      'ROLENAME_SCHEMA': (securesystemslib.formats.ROLENAME_SCHEMA, 'Root'),

      'RSAKEYBITS_SCHEMA': (securesystemslib.formats.RSAKEYBITS_SCHEMA, 4096),

      'PASSWORD_SCHEMA': (securesystemslib.formats.PASSWORD_SCHEMA, 'secret'),

      'PASSWORDS_SCHEMA': (securesystemslib.formats.PASSWORDS_SCHEMA,
          ['pass1', 'pass2']),

      'KEYVAL_SCHEMA': (securesystemslib.formats.KEYVAL_SCHEMA,
          {'public': 'pubkey', 'private': 'privkey'}),

      'PUBLIC_KEYVAL_SCHEMA': (securesystemslib.formats.PUBLIC_KEYVAL_SCHEMA,
          {'public': 'pubkey'}),

      'PUBLIC_KEYVAL_SCHEMA2': (securesystemslib.formats.PUBLIC_KEYVAL_SCHEMA,
          {'public': 'pubkey', 'private': ''}),

      'RSA_SCHEME_SCHEMA_RSASSA_PSS': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsassa-pss-md5'),

      'RSA_SCHEME_SCHEMA_RSASSA_PSS_2': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsassa-pss-sha1'),

      'RSA_SCHEME_SCHEMA_RSASSA_PSS_3': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsassa-pss-sha224'),

      'RSA_SCHEME_SCHEMA_RSASSA_PSS_4': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsassa-pss-sha256'),

      'RSA_SCHEME_SCHEMA_RSASSA_PSS_5': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsassa-pss-sha384'),

      'RSA_SCHEME_SCHEMA_RSASSA_PSS_6': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsassa-pss-sha512'),

      'RSA_SCHEME_SCHEMA_PKCS1v15': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsa-pkcs1v15-md5'),

      'RSA_SCHEME_SCHEMA_PKCS1v15_2': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsa-pkcs1v15-sha1'),

      'RSA_SCHEME_SCHEMA_PKCS1v15_3': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsa-pkcs1v15-sha224'),

      'RSA_SCHEME_SCHEMA_PKCS1v15_4': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsa-pkcs1v15-sha256'),

      'RSA_SCHEME_SCHEMA_PKCS1v15_5': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsa-pkcs1v15-sha384'),

      'RSA_SCHEME_SCHEMA_PKCS1v15_6': (securesystemslib.formats.RSA_SCHEME_SCHEMA,
          'rsa-pkcs1v15-sha512'),

      'KEY_SCHEMA': (securesystemslib.formats.KEY_SCHEMA,
          {'keytype': 'rsa',
           'scheme': 'rsassa-pss-sha256',
           'keyval': {'public': 'pubkey',
           'private': 'privkey'}}),

      'PUBLIC_KEY_SCHEMA': (securesystemslib.formats.KEY_SCHEMA,
          {'keytype': 'rsa',
           'scheme': 'rsassa-pss-sha256',
           'keyval': {'public': 'pubkey'}}),

      'PUBLIC_KEY_SCHEMA2': (securesystemslib.formats.KEY_SCHEMA,
          {'keytype': 'rsa',
           'scheme': 'rsassa-pss-sha256',
           'keyval': {'public': 'pubkey',
                      'private': ''}}),

      'RSAKEY_SCHEMA': (securesystemslib.formats.RSAKEY_SCHEMA,
          {'keytype': 'rsa',
           'scheme': 'rsassa-pss-sha256',
           'keyid': '123456789abcdef',
           'keyval': {'public': 'pubkey',
                      'private': 'privkey'}}),

      'FILEINFO_SCHEMA': (securesystemslib.formats.FILEINFO_SCHEMA,
          {'length': 1024,
           'hashes': {'sha256': 'A4582BCF323BCEF'},
           'custom': {'type': 'paintjob'}}),

      'FILEDICT_SCHEMA': (securesystemslib.formats.FILEDICT_SCHEMA,
          {'metadata/root.json': {'length': 1024,
           'hashes': {'sha256': 'ABCD123'},
           'custom': {'type': 'metadata'}}}),

      'SIGNATURE_SCHEMA': (securesystemslib.formats.SIGNATURE_SCHEMA,
          {'keyid': '123abc',
           'method': 'evp',
           'sig': 'A4582BCF323BCEF'}),

      'SIGNATURESTATUS_SCHEMA': (securesystemslib.formats.SIGNATURESTATUS_SCHEMA,
          {'threshold': 1,
           'good_sigs': ['123abc'],
           'bad_sigs': ['123abc'],
           'unknown_sigs': ['123abc'],
           'untrusted_sigs': ['123abc'],
           'unknown_method_sigs': ['123abc']}),

      'SIGNABLE_SCHEMA': (securesystemslib.formats.SIGNABLE_SCHEMA,
          {'signed': 'signer',
           'signatures': [{'keyid': '123abc',
           'method': 'evp',
           'sig': 'A4582BCF323BCEF'}]}),

      'KEYDICT_SCHEMA': (securesystemslib.formats.KEYDICT_SCHEMA,
          {'123abc': {'keytype': 'rsa',
           'scheme': 'rsassa-pss-sha256',
           'keyval': {'public': 'pubkey', 'private': 'privkey'}}}),

      'KEYDB_SCHEMA': (securesystemslib.formats.KEYDB_SCHEMA,
          {'123abc': {'keytype': 'rsa',
           'keyid': '123456789abcdef',
           'keyval': {'public': 'pubkey', 'private': 'privkey'}}}),

      'ROLE_SCHEMA': (securesystemslib.formats.ROLE_SCHEMA,
          {'keyids': ['123abc'],
           'threshold': 1,
           'paths': ['path1/', 'path2']}),

      'ROLEDICT_SCHEMA': (securesystemslib.formats.ROLEDICT_SCHEMA,
          {'root': {'keyids': ['123abc'],
           'threshold': 1,
           'paths': ['path1/', 'path2']}}),

      'ROOT_SCHEMA': (securesystemslib.formats.ROOT_SCHEMA,
          {'_type': 'root',
           'version': 8,
           'consistent_snapshot': False,
           'expires': '1985-10-21T13:20:00Z',
           'keys': {'123abc': {'keytype': 'rsa',
           'scheme': 'rsassa-pss-sha256',
           'keyval': {'public': 'pubkey',
           'private': 'privkey'}}},
           'roles': {'root': {'keyids': ['123abc'],
           'threshold': 1,
           'paths': ['path1/', 'path2']}}}),

      'TARGETS_SCHEMA': (securesystemslib.formats.TARGETS_SCHEMA,
        {'_type': 'targets',
         'version': 8,
         'expires': '1985-10-21T13:20:00Z',
         'targets': {'metadata/targets.json': {'length': 1024,
         'hashes': {'sha256': 'ABCD123'},
         'custom': {'type': 'metadata'}}},
         'delegations': {'keys': {'123abc': {'keytype':'rsa',
         'scheme': 'rsassa-pss-sha256',
         'keyval': {'public': 'pubkey',
         'private': 'privkey'}}},
         'roles': [{'name': 'root', 'keyids': ['123abc'],
         'threshold': 1,
         'paths': ['path1/', 'path2']}]}}),

      'SNAPSHOT_SCHEMA': (securesystemslib.formats.SNAPSHOT_SCHEMA,
        {'_type': 'snapshot',
         'version': 8,
         'expires': '1985-10-21T13:20:00Z',
         'meta': {'snapshot.json': {'version': 1024}}}),

      'TIMESTAMP_SCHEMA': (securesystemslib.formats.TIMESTAMP_SCHEMA,
        {'_type': 'timestamp',
         'version': 8,
         'expires': '1985-10-21T13:20:00Z',
         'meta': {'metadattimestamp.json': {'length': 1024,
         'hashes': {'sha256': 'AB1245'}}}}),

      'MIRROR_SCHEMA': (securesystemslib.formats.MIRROR_SCHEMA,
        {'url_prefix': 'http://localhost:8001',
         'metadata_path': 'metadata/',
         'targets_path': 'targets/',
         'confined_target_dirs': ['path1/', 'path2/'],
         'custom': {'type': 'mirror'}}),

      'MIRRORDICT_SCHEMA': (securesystemslib.formats.MIRRORDICT_SCHEMA,
        {'mirror1': {'url_prefix': 'http://localhost:8001',
         'metadata_path': 'metadata/',
         'targets_path': 'targets/',
         'confined_target_dirs': ['path1/', 'path2/'],
         'custom': {'type': 'mirror'}}}),

      'MIRRORLIST_SCHEMA': (securesystemslib.formats.MIRRORLIST_SCHEMA,
        {'_type': 'mirrors',
         'version': 8,
         'expires': '1985-10-21T13:20:00Z',
         'mirrors': [{'url_prefix': 'http://localhost:8001',
         'metadata_path': 'metadata/',
         'targets_path': 'targets/',
         'confined_target_dirs': ['path1/', 'path2/'],
         'custom': {'type': 'mirror'}}]})}

    # Iterate 'valid_schemas', ensuring each 'valid_schema' correctly matches
    # its respective 'schema_type'.
    for schema_name, (schema_type, valid_schema) in six.iteritems(valid_schemas):
      if not schema_type.matches(valid_schema):
        print('bad schema: ' + repr(valid_schema))

      self.assertEqual(True, schema_type.matches(valid_schema))

    # Test conditions for invalid schemas.
    # Set the 'valid_schema' of 'valid_schemas' to an invalid
    # value and test that it does not match 'schema_type'.
    for schema_name, (schema_type, valid_schema) in six.iteritems(valid_schemas):
      invalid_schema = 0xBAD

      if isinstance(schema_type, securesystemslib.schema.Integer):
        invalid_schema = 'BAD'
      self.assertEqual(False, schema_type.matches(invalid_schema))




  def test_unix_timestamp_to_datetime(self):
    # Test conditions for valid arguments.
    UNIX_TIMESTAMP_SCHEMA = securesystemslib.formats.UNIX_TIMESTAMP_SCHEMA
    self.assertTrue(datetime.datetime,
        securesystemslib.formats.unix_timestamp_to_datetime(499137720))
    datetime_object = datetime.datetime(1985, 10, 26, 1, 22)
    self.assertEqual(datetime_object,
        securesystemslib.formats.unix_timestamp_to_datetime(499137720))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.unix_timestamp_to_datetime, 'bad')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.unix_timestamp_to_datetime,
        1000000000000000000000)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.unix_timestamp_to_datetime, -1)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.unix_timestamp_to_datetime, ['5'])



  def test_datetime_to_unix_timestamp(self):
    # Test conditions for valid arguments.
    datetime_object = datetime.datetime(2015, 10, 21, 19, 28)
    self.assertEqual(1445455680,
        securesystemslib.formats.datetime_to_unix_timestamp(datetime_object))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.datetime_to_unix_timestamp, 'bad')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.datetime_to_unix_timestamp,
        1000000000000000000000)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.datetime_to_unix_timestamp, ['1'])



  def test_format_base64(self):
    # Test conditions for valid arguments.
    data = 'updateframework'.encode('utf-8')
    self.assertEqual('dXBkYXRlZnJhbWV3b3Jr',
        securesystemslib.formats.format_base64(data))
    self.assertTrue(isinstance(securesystemslib.formats.format_base64(data),
        six.string_types))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.format_base64, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.format_base64, True)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.format_base64, ['123'])


  def test_parse_base64(self):
    # Test conditions for valid arguments.
    base64 = 'dXBkYXRlZnJhbWV3b3Jr'
    self.assertEqual(b'updateframework',
        securesystemslib.formats.parse_base64(base64))
    self.assertTrue(isinstance(securesystemslib.formats.parse_base64(base64),
        six.binary_type))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.parse_base64, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.parse_base64, True)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.parse_base64, ['123'])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        securesystemslib.formats.parse_base64, '/')




  def test_encode_canonical(self):
    # Test conditions for valid arguments.
    encode = securesystemslib.formats.encode_canonical
    result = []
    output = result.append
    bad_output = 123

    self.assertEqual('""', encode(""))
    self.assertEqual('[1,2,3]', encode([1, 2, 3]))
    self.assertEqual('[1,2,3]', encode([1,2,3]))
    self.assertEqual('[]', encode([]))
    self.assertEqual('{}', encode({}))
    self.assertEqual('{"A":[99]}', encode({"A": [99]}))
    self.assertEqual('{"A":true}', encode({"A": True}))
    self.assertEqual('{"B":false}', encode({"B": False}))
    self.assertEqual('{"x":3,"y":2}', encode({"x": 3, "y": 2}))

    self.assertEqual('{"x":3,"y":null}', encode({"x": 3, "y": None}))

    # Condition where 'encode()' sends the result to the callable
    # 'output'.
    self.assertEqual(None, encode([1, 2, 3], output))
    self.assertEqual('[1,2,3]', ''.join(result))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, encode,
        securesystemslib.exceptions.FormatError)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        encode, 8.0)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        encode, {"x": 8.0})
    self.assertRaises(securesystemslib.exceptions.FormatError,
        encode, 8.0, output)

    self.assertRaises(securesystemslib.exceptions.FormatError,
        encode, {"x": securesystemslib.exceptions.FormatError})


# Run unit test.
if __name__ == '__main__':
  unittest.main()
