import patch_outer
from repo import Service


def handle():
    cmd = input()
    return Service.repo.run(cmd)
