package kw.test.vpncapturedata.data;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import kw.test.vpncapturedata.utils.BitUtils;

/**
 * 一个字节是8位   char类型是16位
 *
 * ------------------------------
 * 0-----4-------8---19-------16------------------31
 * 版本  |首部长度 |区分服务器   |总长度
 *      标识     |标志|片偏移
 *生存时间|协议    |首部检验
 * 源IP
 * 目标IP
 * 可选长度
 *
 * https://zhuanlan.zhihu.com/p/638943592
 */

public class IP4Header {
    public byte version;
    public byte IHL;
    public int headerLength;
    public short typeOfService;
    public int totalLength;
    public int identificationAndFlagsAndFragmentOffset;
    public short TTL;
    private short protocolNum;
    public TransportProtocol protocol;
    public int headerChecksum;
    public InetAddress sourceAddress;
    public InetAddress destinationAddress;


    public IP4Header(ByteBuffer buffer) throws UnknownHostException {
        //读取8字节
        byte versionAndIHL = buffer.get();
        //版本
        this.version = (byte) (versionAndIHL >> 4);
        //首部长度
        this.IHL = (byte) (versionAndIHL & 0x0F);
        this.headerLength = this.IHL << 2;

        //服务器类型
        this.typeOfService = BitUtils.getUnsignedByte(buffer.get());
        //总长度
        this.totalLength = BitUtils.getUnsignedShort(buffer.getShort());
        //标识  标志  片位移
        this.identificationAndFlagsAndFragmentOffset = buffer.getInt();
        //生存时间
        this.TTL = BitUtils.getUnsignedByte(buffer.get());
        //协议的个数
        this.protocolNum = BitUtils.getUnsignedByte(buffer.get());
        this.protocol = TransportProtocol.numberToEnum(protocolNum);
        //头部校验和
        this.headerChecksum = BitUtils.getUnsignedShort(buffer.getShort());
        //开始ip
        byte[] addressBytes = new byte[4];
        buffer.get(addressBytes, 0, 4);
        this.sourceAddress = InetAddress.getByAddress(addressBytes);
        //结束IP
        buffer.get(addressBytes, 0, 4);
        this.destinationAddress = InetAddress.getByAddress(addressBytes);

    }

    public void fillHeader(ByteBuffer buffer) {
        buffer.put((byte) (this.version << 4 | this.IHL));
        buffer.put((byte) this.typeOfService);
        buffer.putShort((short) this.totalLength);

        buffer.putInt(this.identificationAndFlagsAndFragmentOffset);

        buffer.put((byte) this.TTL);
        buffer.put((byte) this.protocol.getNumber());
        buffer.putShort((short) this.headerChecksum);

        buffer.put(this.sourceAddress.getAddress());
        buffer.put(this.destinationAddress.getAddress());
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("IP4Header{");
        sb.append("version=").append(version);
        sb.append(", IHL=").append(IHL);
        sb.append(", typeOfService=").append(typeOfService);
        sb.append(", totalLength=").append(totalLength);
        sb.append(", identificationAndFlagsAndFragmentOffset=").append(identificationAndFlagsAndFragmentOffset);
        sb.append(", TTL=").append(TTL);
        sb.append(", protocol=").append(protocolNum).append(":").append(protocol);
        sb.append(", headerChecksum=").append(headerChecksum);
        sb.append(", sourceAddress=").append(sourceAddress.getHostAddress());
        sb.append(", destinationAddress=").append(destinationAddress.getHostAddress());
        sb.append('}');
        return sb.toString();
    }
}
