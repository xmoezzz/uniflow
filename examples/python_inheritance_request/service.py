from django.http import HttpRequest
import os

class BaseRepo:
    def command(self, value):
        return value

class Repo(BaseRepo):
    def run(self, value):
        return self.command(value)

class Controller:
    def __init__(self):
        self.repo = Repo()

    def command(self, value):
        return value

    def handle(self, request):
        cmd = request.GET.get("cmd")
        return self.repo.run(cmd)

controller = Controller()
os.system(controller.handle(HttpRequest()))
