from repo import Repo

class App:
    def __init__(self):
        self.repo = Repo()

    def handle(self, request):
        self.repo.current().execute(request.args.get("q"))
