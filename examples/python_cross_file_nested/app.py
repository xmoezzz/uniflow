from flask import request
from repo import Repo

class Controller:
    def __init__(self):
        self.repo = Repo()

    def handle(self):
        q = request.args.get("q")
        return self.repo.db.execute(q)
