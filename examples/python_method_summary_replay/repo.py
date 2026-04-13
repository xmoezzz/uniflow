import os

class Runner:
    def run(self, cmd):
        os.system(cmd)

class Service:
    def install(self):
        self.runner = Runner()

    @classmethod
    def install_shared(cls):
        cls.shared = Runner()
