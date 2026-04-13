class Repo:
    def run(self, cmd):
        return cmd


def get_repo() -> Repo:
    return Repo()
