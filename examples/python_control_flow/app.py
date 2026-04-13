from flask import request
import subprocess


def handle():
    cmd = request.args.get("cmd")
    if cmd:
        selected = cmd
    else:
        selected = "safe"

    while selected:
        for item in selected:
            try:
                subprocess.run(item)
            except Exception as err:
                return str(err)
        return None
