import os

class Runner:
    def run(self, cmd):
        os.system(cmd)

class Service:
    pass


def install(service):
    service.runner = Runner()
