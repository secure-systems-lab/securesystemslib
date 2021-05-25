#!/usr/bin/env python

"""
<Program Name>
  test_schema.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 2012.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'schema.py'
"""

import unittest
import re

import securesystemslib.exceptions
import securesystemslib.schema as SCHEMA



class TestSchema(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    pass



  def test_Schema(self):
    # Test conditions for the instantation of classes that inherit
    # from class Schema().
    class NewSchema(SCHEMA.Schema):
      def __init__(self):
        pass

    new_schema = NewSchema()
    self.assertRaises(NotImplementedError, new_schema.matches, 'test')

    # Define a new schema.
    class NewSchema2(SCHEMA.Schema):
      def __init__(self, string):
        self._string = string

      def check_match(self, object):
        if self._string != object:
          message = 'Expected: '+repr(self._string)
          raise securesystemslib.exceptions.FormatError(message)

    new_schema2 = NewSchema2('test')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        new_schema2.check_match, 'bad')
    self.assertFalse(new_schema2.matches('bad'))
    self.assertTrue(new_schema2.matches('test'))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        new_schema2.check_match, True)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        new_schema2.check_match, NewSchema2)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        new_schema2.check_match, 123)

    self.assertFalse(new_schema2.matches(True))
    self.assertFalse(new_schema2.matches(NewSchema2))
    self.assertFalse(new_schema2.matches(123))



  def test_Any(self):
    # Test conditions for valid arguments.
    any_schema = SCHEMA.Any()

    self.assertTrue(any_schema.matches('test'))
    self.assertTrue(any_schema.matches(123))
    self.assertTrue(any_schema.matches(['test']))
    self.assertTrue(any_schema.matches({'word':'definition'}))
    self.assertTrue(any_schema.matches(True))



  def test_String(self):
    # Test conditions for valid arguments.
    string_schema = SCHEMA.String('test')

    self.assertTrue(string_schema.matches('test'))

    # Test conditions for invalid arguments.
    self.assertFalse(string_schema.matches(True))
    self.assertFalse(string_schema.matches(['test']))
    self.assertFalse(string_schema.matches(SCHEMA.Schema))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.String, 1)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.String, [1])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.String, {'a': 1})



  def test_AnyString(self):
    # Test conditions for valid arguments.
    anystring_schema = SCHEMA.AnyString()

    self.assertTrue(anystring_schema.matches(''))
    self.assertTrue(anystring_schema.matches('a string'))

    # Test conditions for invalid arguments.
    self.assertFalse(anystring_schema.matches(['a']))
    self.assertFalse(anystring_schema.matches(3))
    self.assertFalse(anystring_schema.matches({'a': 'string'}))



  def test_AnyNonemptyString(self):
    anynonemptystring_schema = SCHEMA.AnyNonemptyString()

    self.assertTrue(anynonemptystring_schema.matches("foo"))

    # Test conditions for invalid arguments.
    self.assertFalse(anynonemptystring_schema.matches(''))
    self.assertFalse(anynonemptystring_schema.matches(['a']))
    self.assertFalse(anynonemptystring_schema.matches(3))
    self.assertFalse(anynonemptystring_schema.matches({'a': 'string'}))



  def test_OneOf(self):
    # Test conditions for valid arguments.
    oneof_schema = SCHEMA.OneOf([SCHEMA.ListOf(SCHEMA.Integer()),
        SCHEMA.String('Hello'), SCHEMA.String('bye')])

    self.assertTrue(oneof_schema.matches([]))
    self.assertTrue(oneof_schema.matches('bye'))
    self.assertTrue(oneof_schema.matches([1,2]))

    # Test conditions for invalid arguments.
    self.assertFalse(oneof_schema.matches(3))
    self.assertFalse(oneof_schema.matches(['Hi']))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.OneOf, 1)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.OneOf, [1])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.OneOf, {'a': 1})
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.OneOf, [SCHEMA.AnyString(), 1])



  def test_AllOf(self):
    # Test conditions for valid arguments.
    allof_schema = SCHEMA.AllOf([SCHEMA.Any(),
        SCHEMA.AnyString(), SCHEMA.String('a')])

    self.assertTrue(allof_schema.matches('a'))

    # Test conditions for invalid arguments.
    self.assertFalse(allof_schema.matches('b'))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.AllOf, 1)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.AllOf, [1])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.AllOf, {'a': 1})
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.AllOf, [SCHEMA.AnyString(), 1])


  def test_Boolean(self):
    # Test conditions for valid arguments.
    boolean_schema = SCHEMA.Boolean()

    self.assertTrue(boolean_schema.matches(True) and boolean_schema.matches(False))

    # Test conditions for invalid arguments.
    self.assertFalse(boolean_schema.matches(11))



  def test_ListOf(self):
    # Test conditions for valid arguments.
    listof_schema = SCHEMA.ListOf(SCHEMA.RegularExpression('(?:..)*'))
    listof2_schema = SCHEMA.ListOf(SCHEMA.Integer(),
        min_count=3, max_count=10)

    self.assertTrue(listof_schema.matches([]))
    self.assertTrue(listof_schema.matches(['Hi', 'this', 'list', 'is',
        'full', 'of', 'even', 'strs']))

    self.assertTrue(listof2_schema.matches([3]*3))
    self.assertTrue(listof2_schema.matches([3]*10))

    # Test conditions for invalid arguments.
    self.assertFalse(listof_schema.matches('hi'))
    self.assertFalse(listof_schema.matches({}))
    self.assertFalse(listof_schema.matches(['This', 'one', 'is not']))

    self.assertFalse(listof2_schema.matches([3]*2))
    self.assertFalse(listof2_schema.matches(([3]*11)))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.ListOf, 1)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.ListOf, [1])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.ListOf, {'a': 1})



  def test_Integer(self):
    # Test conditions for valid arguments.
    integer_schema = SCHEMA.Integer()

    self.assertTrue(integer_schema.matches(99))
    self.assertTrue(SCHEMA.Integer(lo=10, hi=30).matches(25))

    # Test conditions for invalid arguments.
    self.assertFalse(integer_schema.matches(False))
    self.assertFalse(integer_schema.matches('a string'))
    self.assertFalse(SCHEMA.Integer(lo=10, hi=30).matches(5))



  def test_DictOf(self):
    # Test conditions for valid arguments.
    dictof_schema = SCHEMA.DictOf(SCHEMA.RegularExpression(r'[aeiou]+'),
        SCHEMA.Struct([SCHEMA.AnyString(), SCHEMA.AnyString()]))

    self.assertTrue(dictof_schema.matches({}))
    self.assertTrue(dictof_schema.matches({'a': ['x', 'y'], 'e' : ['', '']}))

    # Test conditions for invalid arguments.
    self.assertFalse(dictof_schema.matches(''))
    self.assertFalse(dictof_schema.matches({'a': ['x', 3], 'e' : ['', '']}))
    self.assertFalse(dictof_schema.matches({'a': ['x', 'y'], 'e' : ['', ''],
        'd' : ['a', 'b']}))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.DictOf, 1, 1)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.DictOf, [1], [1])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.DictOf, {'a': 1}, 1)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.DictOf, SCHEMA.AnyString(), 1)



  def test_Optional(self):
    # Test conditions for valid arguments.
    optional_schema = SCHEMA.Object(k1=SCHEMA.String('X'),
        k2=SCHEMA.Optional(SCHEMA.String('Y')))

    self.assertTrue(optional_schema.matches({'k1': 'X', 'k2': 'Y'}))
    self.assertTrue(optional_schema.matches({'k1': 'X'}))

    # Test conditions for invalid arguments.
    self.assertFalse(optional_schema.matches({'k1': 'X', 'k2': 'Z'}))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Optional, 1)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Optional, [1])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Optional, {'a': 1})



  def test_Object(self):
    # Test conditions for valid arguments.
    object_schema = SCHEMA.Object(a=SCHEMA.AnyString(),
        bc=SCHEMA.Struct([SCHEMA.Integer(), SCHEMA.Integer()]))

    self.assertTrue(object_schema.matches({'a':'ZYYY', 'bc':[5,9]}))
    self.assertTrue(object_schema.matches({'a':'ZYYY', 'bc':[5,9], 'xx':5}))

    # Test conditions for invalid arguments.
    self.assertFalse(object_schema.matches({'a':'ZYYY', 'bc':[5,9,3]}))
    self.assertFalse(object_schema.matches({'a':'ZYYY'}))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Object, a='a')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Object, a=[1])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Object, a=SCHEMA.AnyString(), b=1)

    # Test condition for invalid non-dict arguments.
    self.assertFalse(object_schema.matches([{'a':'XYZ'}]))
    self.assertFalse(object_schema.matches(8))



  def test_Struct(self):
    # Test conditions for valid arguments.
    struct_schema = SCHEMA.Struct([SCHEMA.ListOf(SCHEMA.AnyString()),
        SCHEMA.AnyString(), SCHEMA.String('X')])
    struct2_schema = SCHEMA.Struct([SCHEMA.String('X')], allow_more=True)
    struct3_schema = SCHEMA.Struct([SCHEMA.String('X'),
        SCHEMA.Integer()], [SCHEMA.Integer()])

    self.assertTrue(struct_schema.matches([[], 'Q', 'X']))

    self.assertTrue(struct2_schema.matches(['X']))
    self.assertTrue(struct2_schema.matches(['X', 'Y']))
    self.assertTrue(struct2_schema.matches(['X', ['Y', 'Z']]))

    self.assertTrue(struct3_schema.matches(['X', 3]))
    self.assertTrue(struct3_schema.matches(['X', 3, 9]))

    # Test conditions for invalid arguments.
    self.assertFalse(struct_schema.matches(False))
    self.assertFalse(struct_schema.matches('Foo'))
    self.assertFalse(struct_schema.matches([[], 'Q', 'D']))
    self.assertFalse(struct_schema.matches([[3], 'Q', 'X']))
    self.assertFalse(struct_schema.matches([[], 'Q', 'X', 'Y']))

    self.assertFalse(struct2_schema.matches([]))
    self.assertFalse(struct2_schema.matches([['X']]))

    self.assertFalse(struct3_schema.matches([]))
    self.assertFalse(struct3_schema.matches({}))
    self.assertFalse(struct3_schema.matches(['X']))
    self.assertFalse(struct3_schema.matches(['X', 3, 9, 11]))
    self.assertFalse(struct3_schema.matches(['X', 3, 'A']))

    # Test conditions for invalid arguments in a schema definition.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Struct, 1)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Struct, [1])
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Struct, {'a': 1})
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.Struct, [SCHEMA.AnyString(), 1])



  def test_RegularExpression(self):
    # Test conditions for valid arguments.
    # RegularExpression(pattern, modifiers, re_object, re_name).
    re_schema = SCHEMA.RegularExpression('h.*d')

    self.assertTrue(re_schema.matches('hello world'))

    # Provide a pattern that contains the trailing '$'
    re_schema_2 = SCHEMA.RegularExpression(pattern='abc$',
        modifiers=0, re_object=None, re_name='my_re')

    self.assertTrue(re_schema_2.matches('abc'))

    # Test for valid optional arguments.
    compiled_re = re.compile('^[a-z].*')
    re_schema_optional = SCHEMA.RegularExpression(pattern='abc',
        modifiers=0, re_object=compiled_re, re_name='my_re')
    self.assertTrue(re_schema_optional.matches('abc'))

    # Valid arguments, but the 'pattern' argument is unset (required if the
    # 're_object' is 'None'.)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.RegularExpression, None, 0, None, None)

    # Valid arguments, 're_name' is unset, and 'pattern' is None.  An exception
    # is not raised, but 're_name' is set to 'pattern'.
    re_schema_optional = SCHEMA.RegularExpression(pattern=None,
        modifiers=0, re_object=compiled_re, re_name=None)

    self.assertTrue(re_schema_optional.matches('abc'))
    self.assertTrue(re_schema_optional._re_name == 'pattern')

    # Test conditions for invalid arguments.
    self.assertFalse(re_schema.matches('Hello World'))
    self.assertFalse(re_schema.matches('hello world!'))
    self.assertFalse(re_schema.matches([33, 'Hello']))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.RegularExpression, 8)



  def test_LengthString(self):
    # Test conditions for valid arguments.
    length_string = SCHEMA.LengthString(11)

    self.assertTrue(length_string.matches('Hello World'))
    self.assertTrue(length_string.matches('Hello Marty'))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.LengthString, 'hello')

    self.assertFalse(length_string.matches('hello'))
    self.assertFalse(length_string.matches(8))



  def test_LengthBytes(self):
    # Test conditions for valid arguments.
    length_bytes = SCHEMA.LengthBytes(11)

    self.assertTrue(length_bytes.matches(b'Hello World'))
    self.assertTrue(length_bytes.matches(b'Hello Marty'))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.LengthBytes, 'hello')
    self.assertRaises(securesystemslib.exceptions.FormatError,
        SCHEMA.LengthBytes, True)

    self.assertFalse(length_bytes.matches(b'hello'))
    self.assertFalse(length_bytes.matches(8))



  def test_AnyBytes(self):
    # Test conditions for valid arguments.
    anybytes_schema = SCHEMA.AnyBytes()

    self.assertTrue(anybytes_schema.matches(b''))
    self.assertTrue(anybytes_schema.matches(b'a string'))

    # Test conditions for invalid arguments.
    self.assertFalse(anybytes_schema.matches('a string'))
    self.assertFalse(anybytes_schema.matches(['a']))
    self.assertFalse(anybytes_schema.matches(3))
    self.assertFalse(anybytes_schema.matches({'a': 'string'}))


# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
