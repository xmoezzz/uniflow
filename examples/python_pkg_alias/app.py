import pkg.repo as repo_mod


class Controller:
    def handle(self):
        db = repo_mod.make_db()
        return db.execute(repo_mod.read_value())
