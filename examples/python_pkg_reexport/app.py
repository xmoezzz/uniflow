from flask import request
from pkg import make_repo

class App:
    def run(self):
        return make_repo().db.execute(request.args.get("q"))
