package kw.test.vpncapturedata.parse;


import android.util.Log;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import kw.test.vpncapturedata.constant.Constant;
import kw.test.vpncapturedata.data.Packet;
import kw.test.vpncapturedata.data.TCPHeader;
import kw.test.vpncapturedata.utils.ByteBufferPool;
import kw.test.vpncapturedata.utils.TCB;

public class TCPInput implements Runnable {
    private static final String TAG = TCPInput.class.getSimpleName();
    private static final int HEADER_SIZE = Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE;

    private ConcurrentLinkedQueue<ByteBuffer> outputQueue;
    private Selector selector;

    public TCPInput(ConcurrentLinkedQueue<ByteBuffer> outputQueue, Selector selector) {
        this.outputQueue = outputQueue;
        this.selector = selector;
    }

    @Override
    public void run() {
        try {
            Log.d(TAG, "Started");
            while (!Thread.interrupted()) {
                int readyChannels = selector.select();


                if (readyChannels == 0) {
                    Thread.sleep(10);
                    continue;
                }

                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> keyIterator = keys.iterator();

                while (keyIterator.hasNext() && !Thread.interrupted()) {
                    SelectionKey key = keyIterator.next();
                    if (key.isValid()) {
                        if (key.isConnectable())
                            processConnect(key, keyIterator);
                        else if (key.isReadable())
                            processInput(key, keyIterator);
                    }
                }
            }
        } catch (InterruptedException e) {
            Log.i("VPN", "Stopping");
        } catch (IOException e) {

            Log.w("VPN", e.toString(), e);
        }
    }

    private void processConnect(SelectionKey key, Iterator<SelectionKey> keyIterator) {
        TCB tcb = (TCB) key.attachment();
        Packet referencePacket = tcb.referencePacket;
        try {
            if (tcb.channel.finishConnect()) {
                keyIterator.remove();
                tcb.status = TCB.TCBStatus.SYN_RECEIVED;

                // TODO: Set MSS for receiving larger packets from the device
                ByteBuffer responseBuffer = ByteBufferPool.acquire();
                referencePacket.updateTCPBuffer(responseBuffer, (byte) (TCPHeader.SYN | TCPHeader.ACK),
                        tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);

                byte[] data = new byte[responseBuffer.remaining()];
                responseBuffer.get(data);

                outputQueue.offer(responseBuffer);

                tcb.mySequenceNum++; // SYN counts as a byte
                key.interestOps(SelectionKey.OP_READ);
            }
        } catch (IOException e) {
            Log.e(TAG, "Connection error: " + tcb.ipAndPort, e);
            ByteBuffer responseBuffer = ByteBufferPool.acquire();
            referencePacket.updateTCPBuffer(responseBuffer, (byte) TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
            outputQueue.offer(responseBuffer);
            TCB.closeTCB(tcb);
        }
    }

    private void processInput(SelectionKey key, Iterator<SelectionKey> keyIterator) {
        keyIterator.remove();
        ByteBuffer receiveBuffer = ByteBufferPool.acquire();
        // Leave space for the header
        receiveBuffer.position(HEADER_SIZE);

        TCB tcb = (TCB) key.attachment();
        synchronized (tcb) {
            Packet referencePacket = tcb.referencePacket;
            SocketChannel inputChannel = (SocketChannel) key.channel();
            int readBytes;
            try {
                readBytes = inputChannel.read(receiveBuffer);
            } catch (IOException e) {
                Log.e(TAG, "Network read error: " + tcb.ipAndPort, e);
                referencePacket.updateTCPBuffer(receiveBuffer, (byte) TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
                outputQueue.offer(receiveBuffer);
                TCB.closeTCB(tcb);
                return;
            }

            if (readBytes == -1) {
                // End of stream, stop waiting until we push more data
                key.interestOps(0);
                tcb.waitingForNetworkData = false;

                if (tcb.status != TCB.TCBStatus.CLOSE_WAIT)
                {
                    ByteBufferPool.release(receiveBuffer);
                    return;
                }

                tcb.status = TCB.TCBStatus.LAST_ACK;
                referencePacket.updateTCPBuffer(receiveBuffer, (byte) TCPHeader.FIN, tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
                tcb.mySequenceNum++; // FIN counts as a byte
            } else {
                // XXX: We should ideally be splitting segments by MTU/MSS, but this seems to work without
                referencePacket.updateTCPBuffer(receiveBuffer, (byte) (TCPHeader.PSH | TCPHeader.ACK),
                        tcb.mySequenceNum, tcb.myAcknowledgementNum, readBytes);
                tcb.mySequenceNum += readBytes; // Next sequence number
                receiveBuffer.position(HEADER_SIZE + readBytes);
                try {
                    test(receiveBuffer, readBytes, tcb);
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }
        outputQueue.offer(receiveBuffer);
    }

    private static void test(ByteBuffer byteBuffer1, int readBytes, TCB tcb) {

//        // ✅ 复制 payload，不影响原 Buffer
//        byte[] payload = new byte[readBytes];
//        ByteBuffer duplicate = byteBuffer1.duplicate();
//        duplicate.position(HEADER_SIZE);
//        duplicate.get(payload);
////        // ✅ 拼接响应数据
//        try {
//            tcb.responseBuffer.write(payload);
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//
////         ✅ 打印明文 HTTP 响应（仅 port 80）
//        Log.i("VPN",tcb.ipAndPort);
////        if (tcb.ipAndPort.contains("80")) {
//            String fullResponse = new String(tcb.responseBuffer.toByteArray(), StandardCharsets.UTF_8);
//            int headerEndIndex = fullResponse.indexOf("\r\n\r\n");
//            if (headerEndIndex != -1) {
//                int contentLength = 0;
//                Matcher m = Pattern.compile("Content-Length: (\\d+)", Pattern.CASE_INSENSITIVE).matcher(fullResponse);
//                if (m.find()) {
//                    contentLength = Integer.parseInt(m.group(1));
//                }
//
//                int expectedLength = headerEndIndex + 4 + contentLength;
//                if (tcb.responseBuffer.size() >= expectedLength) {
//                    Log.d("VPN", "完整 HTTP 响应:\n" + fullResponse.substring(0, expectedLength));
//
//                    // 清空或保留多余数据
//                    byte[] leftover = tcb.responseBuffer.toByteArray();
//                    tcb.responseBuffer.reset();
//                    if (leftover.length > expectedLength) {
//                        tcb.responseBuffer.write(leftover, expectedLength, leftover.length - expectedLength);
//                    }
//                }
////            }
//        }
    }
}
