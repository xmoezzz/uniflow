from service.repo import make_repo
from flask import request

class Controller:
    def handle(self):
        repo = make_repo()
        return repo.db.execute(request.args.get("q"))
