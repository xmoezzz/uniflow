import repo


def load(cmd):
    return repo.old(cmd)


class Service:
    pass


repo.run = load
Service.run = load


def handle_module():
    return repo.run(input())


def handle_service():
    factory = Service
    svc = factory()
    return svc.run(input())
