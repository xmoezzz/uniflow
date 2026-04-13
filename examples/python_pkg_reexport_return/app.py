from pkg import make_repo

class Controller:
    def run(self):
        db = make_repo()
        return db.execute(db.seed())
