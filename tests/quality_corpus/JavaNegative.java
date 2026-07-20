import java.security.MessageDigest;
class JavaNegative { byte[] f(byte[] x) throws Exception { String u = "https://example.invalid"; return MessageDigest.getInstance("SHA-256").digest(x); } }
