import os


def handle():
    cmd = os.getenv("CMD")
    os.system(cmd)
