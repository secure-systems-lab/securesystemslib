"""Serialization module provides abstract base classes and concrete
implementations to serialize and deserialize objects.
"""

import abc
from typing import Any


class BaseDeserializer(metaclass=abc.ABCMeta):
    """Abstract base class for deserialization of objects."""

    @abc.abstractmethod
    def deserialize(self, raw_data: bytes) -> Any:
        """Deserialize bytes to a specific object."""
        raise NotImplementedError


class BaseSerializer(metaclass=abc.ABCMeta):
    """Abstract base class for serialization of objects."""

    @abc.abstractmethod
    def serialize(self, obj: Any) -> bytes:
        """Serialize an object to bytes."""
        raise NotImplementedError
