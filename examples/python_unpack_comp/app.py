from flask import request
import os


def handle():
    pair = (request.args.get("cmd"), "safe")
    cmd, fallback = pair
    payload = {"cmd": cmd, "fallback": fallback}
    cmds = [value for key, value in payload.items()]
    for key, value in payload.items():
        os.system(value)
    return cmds[0]
