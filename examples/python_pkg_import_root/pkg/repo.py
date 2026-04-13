from .db import DB
from flask import request


def make_db():
    return DB()


def read_value():
    return request.args.get("q")
