import os

class Runner:
    def run(self, cmd):
        os.system(cmd)

class Service:
    def __init__(self):
        self.runner = Runner()
