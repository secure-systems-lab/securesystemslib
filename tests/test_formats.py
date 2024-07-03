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

import unittest

import securesystemslib.formats


class TestFormats(unittest.TestCase):
    def test_encode_canonical(self):
        # Test conditions for valid arguments.
        encode = securesystemslib.formats.encode_canonical
        result = []
        output = result.append

        self.assertEqual('""', encode(""))
        self.assertEqual("[1,2,3]", encode([1, 2, 3]))
        self.assertEqual("[1,2,3]", encode([1, 2, 3]))
        self.assertEqual("[]", encode([]))
        self.assertEqual("{}", encode({}))
        self.assertEqual('{"A":[99]}', encode({"A": [99]}))
        self.assertEqual('{"A":true}', encode({"A": True}))
        self.assertEqual('{"B":false}', encode({"B": False}))
        self.assertEqual('{"x":3,"y":2}', encode({"x": 3, "y": 2}))

        self.assertEqual('{"x":3,"y":null}', encode({"x": 3, "y": None}))

        # Test condition with escaping " and \
        self.assertEqual('"\\""', encode('"'))
        self.assertEqual('"\\\\"', encode("\\"))
        self.assertEqual('"\\\\\\""', encode('\\"'))

        # Condition where 'encode()' sends the result to the callable
        # 'output'.
        self.assertEqual(None, encode([1, 2, 3], output))
        self.assertEqual("[1,2,3]", "".join(result))

        # Test conditions for invalid arguments.
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            encode,
            securesystemslib.exceptions.FormatError,
        )
        self.assertRaises(securesystemslib.exceptions.FormatError, encode, 8.0)
        self.assertRaises(securesystemslib.exceptions.FormatError, encode, {"x": 8.0})
        self.assertRaises(securesystemslib.exceptions.FormatError, encode, 8.0, output)

        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            encode,
            {"x": securesystemslib.exceptions.FormatError},
        )


# Run unit test.
if __name__ == "__main__":
    unittest.main()
