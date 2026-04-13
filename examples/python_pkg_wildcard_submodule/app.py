from pkg import *

class App:
    def handle(self, request):
        db = repo.make_db()
        return db.execute(request.args.get("q"))
