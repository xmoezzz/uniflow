from flask import request
import json
import subprocess

async def normalize(payload):
    return json.dumps(obj=payload)

class Controller:
    async def handle(self):
        cmd = request.args.get(key="cmd")
        cooked = await normalize(cmd)
        subprocess.run(args=cooked, shell=True)
        return cooked
