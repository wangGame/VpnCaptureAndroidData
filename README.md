# 原理

VPNRunnable将数据得到，分为UDP和TCP.写入队列中。

## 网络传输的信息

以太网头+IPV4/IPV6+TCP/UDP+应用的数据。

### 部分说明

- 以太网 ： 这部分由链路层提供（比如 Ethernet），包含源 MAC、目的 MAC 等。
- IPV4 :
  - 包含源/目的 IP 地址、协议类型（如 6 表示 TCP）等。
  - IPv4 头部长度是 20 字节（无选项时），如果有选项会更长。
  - IPv4 头部中的 protocol 字段标明了后续数据是 TCP（值为 6）、UDP（值为 17）等。
- TCP 头部
  - 紧跟在 IPv4 头部后面。
  - 包含源/目的端口、序列号、确认号、窗口大小等。

### 读取IPV4头信息

vpn读取到数据ByteBuffer。

以太网头是链路层的东西，在这里是没有的，拿到的数据是从IPV4开始的。

IPV4头信息：


```
0-----4-------8---19-------16------------------31

版本  |首部长度 |区分服务器   |总长度

      标识     |标志|片偏移

生存时间|协议    |首部检验
```

```java
//读取8字节   包含两部分
byte versionAndIHL = buffer.get();
//版本
this.version = (byte) (versionAndIHL >> 4);
//首部长度  IP数据报首部的长度
this.IHL = (byte) (versionAndIHL & 0x0F);
this.headerLength = this.IHL << 2;


//服务器类型
this.typeOfService = BitUtils.getUnsignedByte(buffer.get());
//总长度   数据+头部
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
````

## TCP 头信息

只分析HTTP/HTTPS不关心UDP。

- 开始/目标端口号
- TCP序列号
- TCP确认号
- 首部
- 保留


```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Source Port              |    Destination Port           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Data Offset |Res| Flags      |   Window Size                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Checksum                   |   Urgent Pointer              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Options (可选字段) ...                                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```java
//开始 
this.sourcePort = BitUtils.getUnsignedShort(buffer.getShort());
//结束
this.destinationPort = BitUtils.getUnsignedShort(buffer.getShort());
//序列号
this.sequenceNumber = BitUtils.getUnsignedInt(buffer.getInt());
//确认号
this.acknowledgementNumber = BitUtils.getUnsignedInt(buffer.getInt());
//首部+保留字
this.dataOffsetAndReserved = buffer.get();
//
headerLength = ((dataOffsetAndReserved & 0xFF) >> 4) * 4;
//窗口大小
this.flags = buffer.get();
this.window = BitUtils.getUnsignedShort(buffer.getShort());
//校验位
this.checksum = BitUtils.getUnsignedShort(buffer.getShort());
//紧急指针
this.urgentPointer = BitUtils.getUnsignedShort(buffer.getShort());
//Options (可选字段) ..
int optionsLength = this.headerLength - TCP_HEADER_SIZE;
if (optionsLength > 0){
  optionsAndPadding = new byte[optionsLength];
  buffer.get(optionsAndPadding, 0, optionsLength);
}
```

