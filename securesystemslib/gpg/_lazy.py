"""
<Module Name>
  _lazy.py

<Author>
  Zachary Newman <zjn@chainguard.dev>

<Started>
  Oct 13, 2022

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  helpers for backwards compatibility when replacing constants with functions.

  AKA crimes against Python
"""
from typing import Callable, TypeVar, Type, Any
import inspect

T = TypeVar('T')

def wrap_thunk(thunk: Callable[[], T]):
  """Wraps ``thunk`` in an object that acts like the result of calling it."""

  called = False
  value = None

  def lazy():
    nonlocal called, value
    if not called:
      value = thunk()
      called = True
    return value

  superclass: Type[Any] = inspect.signature(thunk).return_annotation
  if superclass in (bool,):
    superclass = object

  class Wrapper(superclass):  # type: ignore
    """Object passing through to the result of a lazily-called thunk."""

    def __getattribute__(self, attr):
      return getattr(lazy(), attr)

    def __str__(self):
      return str(lazy())

    def __bool__(self):
      return bool(lazy())

  return Wrapper()
