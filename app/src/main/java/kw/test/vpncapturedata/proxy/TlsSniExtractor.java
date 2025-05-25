package kw.test.vpncapturedata.proxy;

public class TlsSniExtractor {
    public static String extractSNI(byte[] clientHello) {
        try {
            int pointer = 0;
            pointer += 5; // TLS Record Header
            pointer += 38; // Skip to Session ID length
            int sessionIdLen = clientHello[pointer++] & 0xFF;
            pointer += sessionIdLen;
            int cipherLen = ((clientHello[pointer++] & 0xFF) << 8) | (clientHello[pointer++] & 0xFF);
            pointer += cipherLen + 1; // + compression methods
            int extLen = ((clientHello[pointer++] & 0xFF) << 8) | (clientHello[pointer++] & 0xFF);

            int extensionsEnd = pointer + extLen;
            while (pointer < extensionsEnd) {
                int extType = ((clientHello[pointer++] & 0xFF) << 8) | (clientHello[pointer++] & 0xFF);
                int extDataLen = ((clientHello[pointer++] & 0xFF) << 8) | (clientHello[pointer++] & 0xFF);
                if (extType == 0x00) { // SNI
                    pointer += 5; // skip list length + name type + name length
                    int sniLen = ((clientHello[pointer++] & 0xFF) << 8) | (clientHello[pointer++] & 0xFF);
                    return new String(clientHello, pointer, sniLen);
                } else {
                    pointer += extDataLen;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }
}