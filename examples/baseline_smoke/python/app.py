import hashlib
ENDPOINT = "http://example.invalid/api"
def digest(value):
    return hashlib.new("md5", value).digest()
