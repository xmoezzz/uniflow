import os

class Runner:
    def run(self, cmd):
        os.system(cmd)

class Holder:
    def install(self):
        self.runner = Runner()

class Service:
    def __init__(self):
        self.repo = Holder()
