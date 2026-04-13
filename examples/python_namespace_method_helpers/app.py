from repo import Repo, load
import os

globals()["cb"] = load
globals()["factory"] = Repo


def handle_get(cmd):
    cb = globals().get("cb")
    return os.system(cb(cmd))


def handle_pop(cmd):
    cb = globals().pop("cb")
    return os.system(cb(cmd))


def handle_setdefault(cmd):
    cb = globals().setdefault("cb2", load)
    return os.system(cb(cmd))


def handle_factory(cmd):
    factory = globals().get("factory")
    repo = factory()
    return os.system(repo.run(cmd))
