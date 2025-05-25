package kw.test.vpncapturedata.data;

import android.os.Build;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class PacketTest {
    public static final int IP_HEADER_MIN_LENGTH = 20;
    public static final int TCP_HEADER_MIN_LENGTH = 20;
    public ByteBuffer buffer;
    public int ipVersion;
    public int protocol;
    public InetAddress sourceIp;
    public InetAddress destIp;
    public int sourcePort;
    public int destPort;
    public ByteBuffer payload;

    public PacketTest(ByteBuffer rawBuffer) throws IOException {
        buffer = rawBuffer;

        // IP 版本
        int versionAndHeaderLength = buffer.get(0);
        ipVersion = (versionAndHeaderLength >> 4) & 0xF;
        if (ipVersion != 4) throw new IOException("Only IPv4 supported");

        protocol = buffer.get(9) & 0xFF;

        // IP 地址
        byte[] src = new byte[4];
        byte[] dst = new byte[4];
        buffer.position(12);
        buffer.get(src);
        buffer.get(dst);
        sourceIp = InetAddress.getByAddress(src);
        destIp = InetAddress.getByAddress(dst);

        // 端口
        int ipHeaderLength = (versionAndHeaderLength & 0x0F) * 4;
        buffer.position(ipHeaderLength);
        sourcePort = buffer.getShort() & 0xFFFF;
        destPort = buffer.getShort() & 0xFFFF;

        // Payload
        int totalLength = (buffer.getShort(2) & 0xFFFF);
        int payloadLength = totalLength - ipHeaderLength - TCP_HEADER_MIN_LENGTH;
        buffer.position(ipHeaderLength + TCP_HEADER_MIN_LENGTH);
        payload = buffer.slice(); // 剩余为有效负载
        payload.limit(payloadLength);
    }

    @Override
    public String toString() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            return "Packet{ip=" + sourceIp + ":" + sourcePort + " -> " +
                    destIp + ":" + destPort + ", protocol=" + protocol +
                    "data" + new String(payload.array(), payload.position(), payload.remaining(), StandardCharsets.UTF_8) +
                    "}";
        }else {
            return "Packet{ip=" + sourceIp + ":" + sourcePort + " -> " +
                    destIp + ":" + destPort + ", protocol=" + protocol +
                    "data" + new String(payload.array(), payload.position(), payload.remaining()) +
                    "}";
        }
    }
}
