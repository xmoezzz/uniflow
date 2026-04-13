class Db:
    def execute(self, sql):
        return sql


class Repo:
    def __init__(self):
        self.db = Db()
