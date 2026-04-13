from flask import request
from pkg import *
import pkg as root_pkg


class App:
    def handle(self):
        value = request.values.get("q")
        db1 = make_repo()
        db2 = root_pkg.repo.make_repo()
        items = [db1]
        vals = {"primary": db2}
        items[0].execute(value)
        vals["primary"].execute(value)
