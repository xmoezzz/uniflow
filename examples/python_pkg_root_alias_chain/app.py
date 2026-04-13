import pkg as root_pkg

class App:
    def run(self, request):
        return root_pkg.repo.make_db().execute(request.args.get("q"))
