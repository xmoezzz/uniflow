from repo import Repo


def deco(fn):
    def wrapper(self):
        self.repo = Repo()
        return fn(self)
    return wrapper


class Service:
    @deco
    def install(self):
        return None


def handle():
    cmd = input()
    svc = Service()
    svc.install()
    return svc.repo.run(cmd)
