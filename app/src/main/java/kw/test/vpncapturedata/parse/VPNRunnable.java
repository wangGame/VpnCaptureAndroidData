package kw.test.vpncapturedata.parse;

import android.util.Log;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.concurrent.ConcurrentLinkedQueue;

import kw.test.vpncapturedata.data.Packet;
import kw.test.vpncapturedata.utils.ByteBufferPool;

/**
 * 处理 接收来的数据  将数据分为TCP 和 UDP
 */
public class VPNRunnable implements Runnable {
    private static final String TAG = VPNRunnable.class.getSimpleName();

    private FileDescriptor vpnFileDescriptor;

    private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
    private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
    private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;

    public VPNRunnable(FileDescriptor vpnFileDescriptor,
                       ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue,
                       ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue,
                       ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue) {
        this.vpnFileDescriptor = vpnFileDescriptor;
        this.deviceToNetworkUDPQueue = deviceToNetworkUDPQueue;
        this.deviceToNetworkTCPQueue = deviceToNetworkTCPQueue;
        this.networkToDeviceQueue = networkToDeviceQueue;
    }

    @Override
    public void run() {
        Log.i(TAG, "Started");

        FileChannel vpnInput = new FileInputStream(vpnFileDescriptor).getChannel();
        FileChannel vpnOutput = new FileOutputStream(vpnFileDescriptor).getChannel();

        try {
            ByteBuffer bufferToNetwork = null;
            boolean dataSent = true;
            boolean dataReceived;
            while (!Thread.interrupted()) {
                if (dataSent) {
                    //如果设置了参数，那么取出上一个buffer继续加入数据
                    bufferToNetwork = ByteBufferPool.acquire();
                }else {
                    //否则清除掉，重新写入
                    bufferToNetwork.clear();
                }
                //从vpn中读取数据
                int readBytes = vpnInput.read(bufferToNetwork);
                if (readBytes > 0) {
                    dataSent = true;
                    //读模式
                    bufferToNetwork.flip();
                    Packet packet = null;
                    try {
                        packet = new Packet(bufferToNetwork);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    //加入到tcp或者udp队列中
                    if (packet.isUDP()) {
                        deviceToNetworkUDPQueue.offer(packet);
                    } else if (packet.isTCP()) {
                        deviceToNetworkTCPQueue.offer(packet);
                    } else {
                        Log.w(TAG, "Unknown packet type");
                        dataSent = false;
                    }
                } else {
                    dataSent = false;
                }
                ByteBuffer bufferFromNetwork = networkToDeviceQueue.poll();
                if (bufferFromNetwork != null) {
                    //读取
                    bufferFromNetwork.flip();
                    while (bufferFromNetwork.hasRemaining()) {
                        vpnOutput.write(bufferFromNetwork);
                        byte[] data = new byte[bufferFromNetwork.remaining()];
                        bufferFromNetwork.get(data);
                        if (data.length>10) {
                            Log.v("kw vpn tcp",new String(data));
                        }
                    }
                    dataReceived = true;

                    ByteBufferPool.release(bufferFromNetwork);
                } else {
                    dataReceived = false;
                }

                // TODO: Sleep-looping is not very battery-friendly, consider blocking instead
                // Confirm if throughput with ConcurrentQueue is really higher compared to BlockingQueue
                if (!dataSent && !dataReceived)
                    Thread.sleep(10);
            }
        }
        catch (InterruptedException e) {
            Log.i(TAG, "Stopping");
        } catch (IOException e) {
            Log.w(TAG, e.toString(), e);
        } finally {
//            closeResources(vpnInput, vpnOutput);
        }
    }
}
