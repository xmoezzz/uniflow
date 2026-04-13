from repo import Repo

class App:
    def __init__(self):
        self.repo = Repo()

    def run(self, sql):
        return self.repo.current().execute(sql)
