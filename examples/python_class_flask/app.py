from flask import request
import subprocess

class QueryBuilder:
    def build(self, user_input):
        self.last = user_input
        return "SELECT * FROM users WHERE name = '".format(user_input)

class Controller:
    def __init__(self):
        self.builder = QueryBuilder()

    def handle(self):
        value = request.args.get("name")
        sql = self.builder.build(value)
        subprocess.run(sql)
        return sql
