from service.db import DB

class Repo:
    def __init__(self):
        self.db = DB()

def make_repo():
    return Repo()
