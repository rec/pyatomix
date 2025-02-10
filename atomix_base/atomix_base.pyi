from __future__ import annotations
import typing
__all__ = ['AtomicFlag', 'AtomicInt']
class AtomicFlag:
    __hash__: typing.ClassVar[None] = None
    @staticmethod
    def _pybind11_conduit_v1_(*args, **kwargs):
        ...
    def __eq__(self, arg0: typing.Any) -> bool:
        ...
    def __getstate__(self) -> tuple:
        ...
    @typing.overload
    def __init__(self) -> None:
        ...
    @typing.overload
    def __init__(self, arg0: bool) -> None:
        ...
    def __neq__(self, arg0: typing.Any) -> bool:
        ...
    def __setstate__(self, arg0: tuple) -> None:
        ...
    def clear(self) -> None:
        ...
    def notify_all(self) -> None:
        ...
    def notify_one(self) -> None:
        ...
    def test(self) -> bool:
        ...
    def test_and_set(self) -> bool:
        ...
    def wait(self, arg0: bool) -> None:
        ...
class AtomicInt:
    __hash__: typing.ClassVar[None] = None
    @staticmethod
    def _pybind11_conduit_v1_(*args, **kwargs):
        ...
    def __add__(self, arg0: int) -> int:
        ...
    def __and__(self, arg0: int) -> int:
        ...
    def __eq__(self, arg0: int) -> bool:
        ...
    def __floordiv__(self, arg0: int) -> int:
        ...
    def __ge__(self, arg0: int) -> bool:
        ...
    def __gt__(self, arg0: int) -> bool:
        ...
    def __iadd__(self, arg0: int) -> AtomicInt:
        ...
    def __iand__(self, arg0: int) -> AtomicInt:
        ...
    def __ifloordiv__(self, arg0: int) -> AtomicInt:
        ...
    def __imod__(self, arg0: int) -> AtomicInt:
        ...
    def __imul__(self, arg0: int) -> AtomicInt:
        ...
    @typing.overload
    def __init__(self, arg0: int) -> None:
        ...
    @typing.overload
    def __init__(self) -> None:
        ...
    def __ior__(self, arg0: int) -> AtomicInt:
        ...
    def __isub__(self, arg0: int) -> AtomicInt:
        ...
    def __itruediv__(self, arg0: int) -> AtomicInt:
        ...
    def __ixor__(self, arg0: int) -> AtomicInt:
        ...
    def __le__(self, arg0: int) -> bool:
        ...
    def __lt__(self, arg0: int) -> bool:
        ...
    def __mod__(self, arg0: int) -> int:
        ...
    def __mul__(self, arg0: int) -> int:
        ...
    def __neq__(self, arg0: int) -> bool:
        ...
    def __or__(self, arg0: int) -> int:
        ...
    def __rand__(self, arg0: int) -> int:
        ...
    def __rfloordiv__(self, arg0: int) -> int:
        ...
    def __rmod__(self, arg0: int) -> int:
        ...
    def __rmul__(self, arg0: int) -> int:
        ...
    def __ror__(self, arg0: int) -> int:
        ...
    def __rsub__(self, arg0: int) -> int:
        ...
    def __rtruediv__(self, arg0: int) -> int:
        ...
    def __rxor__(self, arg0: int) -> int:
        ...
    def __str__(self) -> str:
        ...
    def __sub__(self, arg0: int) -> int:
        ...
    def __truediv__(self, arg0: int) -> int:
        ...
    def __xor__(self, arg0: int) -> int:
        ...
    def compare_exchange(self, arg0: int, arg1: int) -> bool:
        ...
    def compare_exchange_weak(self, arg0: int, arg1: int) -> bool:
        ...
    def exchange(self, arg0: int) -> int:
        ...
    def fetch_add(self, arg0: int) -> int:
        ...
    def fetch_sub(self, arg0: int) -> int:
        ...
    def is_lock_free(self) -> bool:
        ...
    def load(self) -> int:
        ...
    def store(self, arg0: int) -> None:
        ...
__version__: str = '0.1.2'
