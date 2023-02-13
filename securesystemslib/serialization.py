"""Serialization module provides abstract base classes and concrete
implementations to serialize and deserialize objects.
"""

import abc
import json
import tempfile
from typing import Any, Dict, Optional

from securesystemslib.exceptions import DeserializationError, SerializationError
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface
from securesystemslib.util import persist_temp_file


# TODO: Use typing.Protocol post python 3.7
class BaseDeserializer(metaclass=abc.ABCMeta):
    """Abstract base class for deserialization of objects."""

    @abc.abstractmethod
    def deserialize(self, raw_data: bytes) -> Any:
        """Deserialize bytes."""

        raise NotImplementedError  # pragma: no cover


class JSONDeserializer(BaseDeserializer):
    """Provides raw to JSON deserialize method."""

    def deserialize(self, raw_data: bytes) -> Dict:
        """Deserialize utf-8 encoded JSON bytes into a dict.

        Arguments:
            raw_data: A utf-8 encoded bytes string.

        Raises:
            securesystemslib.exceptions.DeserializationError: If fails to
                decode raw_data into json.

        Returns:
            dict.
        """

        try:
            return json.loads(raw_data.decode("utf-8"))

        except Exception as e:
            raise DeserializationError("Failed to deserialize bytes") from e


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

    def serialize(self, obj: "JSONSerializable") -> bytes:
        """Serialize an object into utf-8 encoded JSON bytes.

        Arguments:
            obj: An instance of
                ``securesystemslib.serialization.JSONSerializable`` subclass.

        Raises:
            securesystemslib.exceptions.SerializationError: If fails to encode
                into json bytes.

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


class SerializationMixin(metaclass=abc.ABCMeta):
    """Instance of class with ``SerializationMixin`` are to be serialized and
    deserialized using `to_bytes`, `from_bytes`, `to_file` and `from_file`
    methods.
    """

    @staticmethod
    @abc.abstractmethod
    def _default_deserializer() -> BaseDeserializer:
        """Default Deserializer to be used for deserialization."""

        raise NotImplementedError  # pragma: no cover

    @staticmethod
    @abc.abstractmethod
    def _default_serializer() -> BaseSerializer:
        """Default Serializer to be used for serialization."""

        raise NotImplementedError  # pragma: no cover

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        deserializer: Optional[BaseDeserializer] = None,
    ) -> Any:
        """Loads the object from raw data.

        Arguments:
            data: bytes content.
            deserializer: ``securesystemslib.serialization.BaseDeserializer``
                implementation to use.
        Raises:
            securesystemslib.exceptions.DeserializationError: The file cannot
                be deserialized.
        Returns:
            Deserialized object.
        """

        if deserializer is None:
            deserializer = cls._default_deserializer()

        return deserializer.deserialize(data)

    @classmethod
    def from_file(
        cls,
        filename: str,
        deserializer: Optional[BaseDeserializer] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ) -> Any:
        """Loads object from file storage.

        Arguments:
            filename: Path to read the file from.
            deserializer: ``securesystemslib.serialization.BaseDeserializer``
                subclass instance that implements the desired wireline
                format deserialization.
            storage_backend: Object that implements
                ``securesystemslib.storage.StorageBackendInterface``.
                Default is ``securesystemslib.storage.FilesystemBackend``
                (i.e. a local file).
        Raises:
            securesystemslib.exceptions.StorageError: The file cannot be read.
            securesystemslib.exceptions.DeserializationError: The file cannot
                be deserialized.
        Returns:
            Deserialized object.
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
            serializer: ``securesystemslib.serialization.BaseSerializer``
                instance that implements the desired serialization format.
        Raises:
            securesystemslib.exceptions.SerializationError: If object cannot be
                serialized.
        """

        if serializer is None:
            serializer = self._default_serializer()

        return serializer.serialize(self)

    def to_file(
        self,
        filename: str,
        serializer: Optional[BaseSerializer] = None,
        storage_backend: Optional[StorageBackendInterface] = None,
    ):
        """Writes object to file storage.

        Note that if a file is first deserialized and then serialized with
        ``to_file()``, the two files are not required to be identical (in case
        of Metadata the signatures are guaranteed to stay valid). If
        byte-for-byte equivalence is required (which is the case when file
        hashes are used in other metadata), the original file should be used
        instead of re-serializing.

        Arguments:
            filename: Path to write the file to.
            serializer: ``securesystemslib.serialization.BaseSerializer``
                instance that implements the desired serialization format.
            storage_backend: Object that implements
                ``securesystemslib.storage.StorageBackendInterface``.
                Default  is ``securesystemslib.storage.FilesystemBackend``
                (i.e. a local file).
        Raises:
            securesystemslib.exceptions.SerializationError: If object cannot
                be serialized.
            securesystemslib.exceptions.StorageError: The file cannot be
                written.
        """

        bytes_data = self.to_bytes(serializer)

        with tempfile.TemporaryFile() as temp_file:
            temp_file.write(bytes_data)
            persist_temp_file(temp_file, filename, storage_backend)


class JSONSerializable(metaclass=abc.ABCMeta):
    """Objects serialized with ``securesystemslib.serialization.JSONSerializer``
    must inherit from this class and implement its ``to_dict`` method.
    """

    @abc.abstractmethod
    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        raise NotImplementedError  # pragma: no cover
