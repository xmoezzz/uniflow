import os

class DB:
    def seed(self):
        return os.getenv("SQL")

    def execute(self, sql):
        return cursor.execute(sql)
