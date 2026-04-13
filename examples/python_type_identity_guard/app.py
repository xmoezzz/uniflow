from repo import Repo


def handle(obj):
    cmd = input()
    if type(obj) is Repo:
        obj.run(cmd)
