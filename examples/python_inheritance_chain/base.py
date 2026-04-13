from db import DB

class BaseRepo:
    def __init__(self):
        self.db = DB()

    def current(self):
        return self.db
