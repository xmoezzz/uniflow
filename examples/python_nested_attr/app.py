from flask import *
import os

class Db:
    def execute(self, sql):
        return sql

class Repo:
    def __init__(self):
        self.db = Db()
        self.args = request.args

    def run(self):
        sql = self.args.get("q")
        return self.db.execute(sql)

class Controller:
    def __init__(self):
        self.repo = Repo()

    def handle(self):
        return self.repo.run()
