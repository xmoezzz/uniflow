from typing import Generic, TypeVar
from repo import Repo

T = TypeVar("T")

class Box(Generic[T]):
    item: T

    def current(self) -> T:
        return self.item

class RepoBox(Box[Repo]):
    pass

def handle(queryset, user_id):
    box = RepoBox()
    current = box.current()
    shaped = queryset.distinct().only("id")
    return current.save(user_id), shaped
