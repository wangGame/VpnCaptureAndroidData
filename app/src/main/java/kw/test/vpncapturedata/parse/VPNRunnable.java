package kw.test.vpncapturedata.parse;

import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.Selector;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import kw.test.vpncapturedata.constant.Constant;
import kw.test.vpncapturedata.data.Packet;
import kw.test.vpncapturedata.data.PacketTest;
import kw.test.vpncapturedata.utils.ByteBufferPool;
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

                if (dataSent)
                    bufferToNetwork = ByteBufferPool.acquire();
                else
                    bufferToNetwork.clear();
                int readBytes = vpnInput.read(bufferToNetwork);
                if (readBytes > 0) {
                    dataSent = true;
                    bufferToNetwork.flip();
                    Packet packet = null;
                    try {
                        packet = new Packet(bufferToNetwork);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    if (packet.isUDP()) {
                        deviceToNetworkUDPQueue.offer(packet);
                    } else if (packet.isTCP()) {
                        deviceToNetworkTCPQueue.offer(packet);
                    } else {
                        Log.w(TAG, "Unknown packet type");
                        Log.w(TAG, packet.ip4Header.toString());
                        dataSent = false;
                    }
                } else {
                    dataSent = false;
                }
                ByteBuffer bufferFromNetwork = networkToDeviceQueue.poll();
                if (bufferFromNetwork != null) {
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
