from flask import request
import subprocess


def dispatch(cmd="echo safe", *, shell=False, **kwargs):
    subprocess.run(args=cmd, shell=shell)


def handle():
    raw = request.args.get(key="cmd")
    dispatch(shell=True, cmd=raw)
