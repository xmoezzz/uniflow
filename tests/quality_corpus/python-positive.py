import hashlib
URL = "http://example.invalid"
def digest(x): return hashlib.new("md5", x).digest()
