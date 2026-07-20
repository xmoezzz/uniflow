import java.security.MessageDigest;
class Main {
    static byte[] digest(byte[] value) throws Exception {
        String endpoint = "http://example.invalid/api";
        System.out.println(endpoint);
        return MessageDigest.getInstance("MD5").digest(value);
    }
}
