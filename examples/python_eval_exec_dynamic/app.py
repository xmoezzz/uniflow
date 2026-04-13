from repo import Repo, load


def handle_eval():
    cmd = input()
    cb = eval("load")
    cb(cmd)


def handle_exec():
    cmd = input()
    exec("repo = Repo()\ncb = repo.run")
    cb(cmd)
