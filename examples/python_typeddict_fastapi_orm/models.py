from typing import NewType, TypeVar
from typing_extensions import NotRequired, Required, TypedDict
import attrs


class Repo:
    def run(self, cmd: str):
        return cmd


RepoId = NewType("RepoId", str)
TRepo = TypeVar("TRepo", bound=Repo)


class Payload(TypedDict):
    repo: Required[TRepo]
    rid: NotRequired[RepoId]


@attrs.define
class Holder:
    repo = attrs.field(factory=Repo)
