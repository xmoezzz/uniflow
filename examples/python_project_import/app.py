from flask import *
from repo import Repo

class Controller:
    def __init__(self):
        self.repo = Repo()

    def handle(self):
        return self.repo.db.execute(request.args.get("q"))
