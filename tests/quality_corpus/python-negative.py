import hashlib
URL = "https://example.invalid"
def digest(x): return hashlib.sha256(x).digest()
