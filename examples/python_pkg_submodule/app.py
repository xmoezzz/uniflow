from pkg import repo

class App:
    def handle(self, request):
        db = repo.make_db()
        sql = request.args.get("q")
        return db.execute(sql)
