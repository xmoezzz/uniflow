import pkg.repo


class Controller:
    def handle(self):
        db = pkg.repo.make_db()
        return db.execute("select " + pkg.repo.read_value())
