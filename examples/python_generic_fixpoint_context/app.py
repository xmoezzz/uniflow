from typing import Generic, TypeVar
from repo import Repo

T = TypeVar("T")

class Box(Generic[T]):
    item: T

    def current(self) -> T:
        return self.item


def wrap(cb):
    return cb


def handle(box: Box[Repo], cmd: str):
    current = box.current()
    cb = wrap(current.run)
    return cb(cmd)
