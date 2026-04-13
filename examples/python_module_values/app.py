from service import get_db

class App:
    def handle(self, request):
        get_db().execute(request.args.get("q"))
