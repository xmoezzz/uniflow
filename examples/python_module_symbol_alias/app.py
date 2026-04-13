from flask import request
from service import get_conn, items, values


class App:
    def handle(self):
        value = request.headers.get("X-Cmd")
        get_conn.execute(value)
        items[0].execute(value)
        values["db"].execute(value)
