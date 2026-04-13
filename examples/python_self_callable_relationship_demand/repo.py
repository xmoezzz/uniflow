from typing import Awaitable, Callable, Self
from sqlalchemy.orm import relationship


class Repo:
    def clone(self) -> Self:
        return self


class Node:
    children = relationship("self", uselist=True)


Handler = Callable[[str], Repo]
PendingRepo = Awaitable[Repo]
