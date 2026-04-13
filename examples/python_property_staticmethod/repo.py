class Repo:
    def run(self, cmd):
        return cmd


class Service:
    @staticmethod
    def make_repo():
        return Repo()

    @property
    def repo(self):
        return self.make_repo()
