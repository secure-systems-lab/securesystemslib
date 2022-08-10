"""Serialization module provides abstract base classes and concrete
implementations to serialize and deserialize objects.
"""

import abc
import json
import tempfile
from typing import Any, Optional

from securesystemslib.exceptions import DeserializationError, SerializationError
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface
from securesystemslib.util import persist_temp_file


class BaseDeserializer(metaclass=abc.ABCMeta):
    """Abstract base class for deserialization of objects."""

    @abc.abstractmethod
    def deserialize(self, raw_data: bytes, cls: Any) -> Any:
        """Deserialize bytes to a specific object."""

        raise NotImplementedError  # pragma: no cover


class JSONDeserializer(BaseDeserializer):
    """Provides raw to JSON deserialize method."""

    def deserialize(self, raw_data: bytes, cls: Any) -> Any:
        """Deserialize utf-8 encoded JSON bytes into an instance of cls.

        Arguments:
            raw_data: A utf-8 encoded bytes string.
            cls: A class type having a from_dict method.

        Returns:
            Object of the provided class type.
        """

        try:
            json_dict = json.loads(raw_data.decode("utf-8"))
            obj = cls.from_dict(json_dict)

        except Exception as e:
            raise DeserializationError("Failed to deserialize bytes") from e

        return obj


class BaseSerializer(metaclass=abc.ABCMeta):
    """Abstract base class for serialization of objects."""

    @abc.abstractmethod
    def serialize(self, obj: Any) -> bytes:
        """Serialize an object to bytes."""

        raise NotImplementedError  # pragma: no cover


class JSONSerializer(BaseSerializer):
    """Provide an object to bytes serialize method.

    Attributes:
        compact: A boolean indicating if the JSON bytes generated in
            'serialize' should be compact by excluding whitespace.
    """

    def __init__(self, compact: bool = False):
        self.indent = 1
        self.separators = (",", ": ")
        if compact:
            self.indent = None
            self.separators = (",", ":")

    def serialize(self, obj: Any) -> bytes:
        """Serialize an object into utf-8 encoded JSON bytes.

        Arguments:
            obj: An object with to_dict method.

        Returns:
            UTF-8 encoded JSON bytes of the object.
        """

        try:
            json_bytes = json.dumps(
                obj.to_dict(),
                indent=self.indent,
                separators=self.separators,
                sort_keys=True,
            ).encode("utf-8")

        except Exception as e:
            raise SerializationError("Failed to serialize JSON") from e

        return json_bytes


class Serializable(metaclass=abc.ABCMeta):
    """Objects with Base class Serializable are to be serialized and
    deserialized using `to_bytes`, `from_bytes`, `to_file` and `from_file`
    methods.
    """

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        deserializer: Optional[BaseDeserializer] = None,
    ) -> "Serializable":
        """Loads the Serializable from raw data.
        Args:
            data: bytes content.
            deserializer: ``BaseDeserializer`` implementation to use.
                Default is JSONDeserializer.
        Raises:
            DeserializationError: The file cannot be deserialized.
        Returns:
            The Serializable object.
        """

        if deserializer is None:
            deserializer = JSONDeserializer()

        return deserializer.deserialize(data, cls)

    @classmethod
    def from_file(
        cls,
        filename: str,
        deserializer: Optional[BaseDeserializer] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ) -> "Serializable":
        """Loads object from file storage.

        Arguments:
            filename: Path to read the file from.
            deserializer: ``BaseDeserializer`` subclass instance that
                implements the desired wireline format deserialization.
            storage_backend: Object that implements
                ``securesystemslib.storage.StorageBackendInterface``.
                Default is ``FilesystemBackend`` (i.e. a local file).
        Raises:
            StorageError: The file cannot be read.
            DeserializationError: The file cannot be deserialized.
        Returns:
            The Serializable object.
        """

        if storage_backend is None:
            storage_backend = FilesystemBackend()

        with storage_backend.get(filename) as file_obj:
            return cls.from_bytes(file_obj.read(), deserializer)

    def to_bytes(self, serializer: Optional[BaseSerializer] = None) -> bytes:
        """Return the serialized file format as bytes.

        Note that if bytes are first deserialized and then serialized with
        ``to_file()``, the two files are not required to be identical (in case
        of Metadata the signatures are guaranteed to stay valid). If
        byte-for-byte equivalence is required (which is the case when content
        hashes are used in other metadata), the original content should be used
        instead of re-serializing.

        Arguments:
            serializer: ``BaseSerializer`` instance that implements the
                desired serialization format. Default is ``JSONSerializer``.
        Raises:
            SerializationError: The Serializable object cannot be serialized.
        """

        if serializer is None:
            serializer = JSONSerializer()

        return serializer.serialize(self)

    def to_file(
        self,
        filename: str,
        serializer: Optional[BaseSerializer] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ) -> None:
        """Writes object to file storage.

        Note that if a file is first deserialized and then serialized with
        ``to_file()``, the two files are not required to be identical (in case
        of Metadata the signatures are guaranteed to stay valid). If
        byte-for-byte equivalence is required (which is the case when file
        hashes are used in other metadata), the original file should be used
        instead of re-serializing.

        Arguments:
            filename: Path to write the file to.
            serializer: ``BaseSerializer`` instance that implements the
                desired serialization format. Default is ``JSONSerializer``.
            storage_backend: ``StorageBackendInterface`` implementation.
                Default  is ``FilesystemBackend`` (i.e. a local file).
        Raises:
            SerializationError: The Serializable object cannot be serialized.
            StorageError: The file cannot be written.
        """

        bytes_data = self.to_bytes(serializer)

        with tempfile.TemporaryFile() as temp_file:
            temp_file.write(bytes_data)
            persist_temp_file(temp_file, filename, storage_backend)
