from dataclasses import dataclass, field
from flask import current_app
from repo import Repo


@dataclass
class Payload:
    repo = field(default_factory=Repo)


def handle():
    payload = Payload()
    sql = current_app.config.get("QUERY")
    return payload.repo.db.execute(sql)
