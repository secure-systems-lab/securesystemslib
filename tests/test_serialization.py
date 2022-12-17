#!/usr/bin/env python

"""Test cases for "serialization.py". """

import json
import os
import shutil
import tempfile
import unittest

from securesystemslib.exceptions import DeserializationError, SerializationError
from securesystemslib.metadata import Envelope, EnvelopeJSONDeserializer
from securesystemslib.serialization import JSONDeserializer, JSONSerializer
from securesystemslib.storage import FilesystemBackend


class TestJSONSerialization(unittest.TestCase):
    """Serialization Test Case."""

    @classmethod
    def setUpClass(cls):
        cls.test_obj = Envelope(
            payload=b"hello world",
            payload_type="http://example.com/HelloWorld",
            signatures=[],
        )
        cls.test_bytes = b'{"payload":"aGVsbG8gd29ybGQ=","payloadType":"http://example.com/HelloWorld","signatures":[]}'

    def test_serializer(self):
        """Test JSONSerializer with DSSE Envelope."""

        serializer = JSONSerializer()

        # Assert SerializationError on serializing a invalid object.
        with self.assertRaises(SerializationError):
            serializer.serialize("not a valid obj")

        # Serialize compact and non compact envelope object into bytes.
        json_bytes = serializer.serialize(self.test_obj)

        serializer = JSONSerializer(compact=True)
        compact_json_bytes = serializer.serialize(self.test_obj)

        # Assert inequality between compact and non compact json bytes.
        self.assertNotEqual(json_bytes, compact_json_bytes)

        # Assert equality with the test bytes.
        self.assertEqual(compact_json_bytes, self.test_bytes)

        # Assert equality between compact and non compact json dict.
        self.assertEqual(json.loads(json_bytes), json.loads(compact_json_bytes))

    def test_deserializer(self):
        """Test JSONDeserializer with DSSE Envelope."""

        deserializer = JSONDeserializer()

        # Assert DeserializationError on invalid json and class.
        with self.assertRaises(DeserializationError):
            deserializer.deserialize(b"not a valid json")

        # Assert Equality between deserialized envelope and test object.
        envelope_dict = deserializer.deserialize(self.test_bytes)
        envelope_obj = Envelope.from_dict(envelope_dict)

        self.assertEqual(envelope_obj, self.test_obj)

    def test_serialization(self):
        """Test JSONDeserializer and JSONSerializer."""

        serializer = JSONSerializer()
        json_bytes = serializer.serialize(self.test_obj)

        deserializer = JSONDeserializer()
        envelope_dict = deserializer.deserialize(json_bytes)
        envelope_obj = Envelope.from_dict(envelope_dict)

        # Assert Equality between original object and deserialized object.
        self.assertEqual(envelope_obj, self.test_obj)


class TestSerializationMixin(unittest.TestCase):
    """SerializationMixin Test Case."""

    def setUp(self):
        self.storage_backend = FilesystemBackend()
        self.temp_dir = tempfile.mkdtemp(dir=os.getcwd())
        self.filepath = os.path.join(self.temp_dir, "testfile")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @classmethod
    def setUpClass(cls):
        cls.test_obj = Envelope(
            payload=b"hello world",
            payload_type="http://example.com/HelloWorld",
            signatures=[],
        )

    def test_to_and_from_file(self):
        """Test to_file and from_file method of Serializable."""

        # Save test_obj to a file.
        self.test_obj.to_file(self.filepath)

        # Load object from the saved file.
        envelope_obj = Envelope.from_file(self.filepath)

        # Test for equality.
        self.assertEqual(envelope_obj, self.test_obj)

    def test_to_and_from_file_with_storage_backend(self):
        """Test to_file and from_file method of Serializable with storage
        backend."""

        # Save test_obj to a file.
        self.test_obj.to_file(
            self.filepath, storage_backend=self.storage_backend
        )

        # Load object from the saved file.
        envelope_obj = Envelope.from_file(
            self.filepath, storage_backend=self.storage_backend
        )

        # Test for equality.
        self.assertEqual(envelope_obj, self.test_obj)

    def test_to_and_from_bytes(self):
        """Test to_bytes and from_bytes method of Serializable."""

        # Serializer object into bytes.
        json_bytes = self.test_obj.to_bytes()

        # Deserialize object from bytes.
        envelope_obj = Envelope.from_bytes(json_bytes)

        # Test for equality.
        self.assertEqual(envelope_obj, self.test_obj)

    def test_to_and_from_bytes_with_serializer(self):
        """Test to_bytes and from_bytes method of Serializable with JSON
        serializer and deserializer."""

        # Serializer object into bytes.
        serializer = JSONSerializer(compact=True)
        json_bytes = self.test_obj.to_bytes(serializer)

        # Deserialize object from bytes.
        deserializer = EnvelopeJSONDeserializer()
        envelope_obj = Envelope.from_bytes(json_bytes, deserializer)

        # Test for equality.
        self.assertEqual(envelope_obj, self.test_obj)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
