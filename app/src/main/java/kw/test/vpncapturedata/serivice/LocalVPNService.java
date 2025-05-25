package kw.test.vpncapturedata.serivice;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Selector;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import kw.test.vpncapturedata.data.Packet;
import kw.test.vpncapturedata.parse.TCPInput;
import kw.test.vpncapturedata.parse.TCPOutput;
import kw.test.vpncapturedata.parse.UDPInput;
import kw.test.vpncapturedata.parse.UDPOutput;
import kw.test.vpncapturedata.parse.VPNRunnable;

public class LocalVPNService extends VpnService {
    private ParcelFileDescriptor vpnInterface;
    private static final String VPN_ADDRESS = "10.0.0.2"; // Only IPv4 support for now
    private static final String VPN_ROUTE = "0.0.0.0"; // Intercept everythin

    //使用线程池来获取数据
    private ExecutorService executorService;

    private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;
    private ConcurrentLinkedQueue<Packet> deviceUDPQueue;
    private ConcurrentLinkedQueue<Packet> deviceTCPQueue;

    private Selector udpSelector;
    private Selector tcpSelector;

    @Override
    public void onCreate() {
        super.onCreate();
        setupVPN();
        try {
            excuteData();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void excuteData() throws Exception {
        udpSelector = Selector.open();
        tcpSelector = Selector.open();
        deviceTCPQueue = new ConcurrentLinkedQueue<>();
        deviceUDPQueue = new ConcurrentLinkedQueue<>();
        networkToDeviceQueue = new ConcurrentLinkedQueue<>();
        executorService = Executors.newFixedThreadPool(5);
        executorService.submit(new UDPInput(networkToDeviceQueue, udpSelector));
        executorService.submit(new UDPOutput(deviceUDPQueue, udpSelector, this));
        executorService.submit(new TCPInput(networkToDeviceQueue, tcpSelector));
        executorService.submit(new TCPOutput(deviceTCPQueue, networkToDeviceQueue, tcpSelector, this));
        executorService.submit(
                new VPNRunnable(vpnInterface.getFileDescriptor(), deviceUDPQueue, deviceTCPQueue, networkToDeviceQueue));
    }

    private void setupVPN() {
        if (vpnInterface == null) {
            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, 32);
            builder.addRoute(VPN_ROUTE, 0);
            vpnInterface = builder.setSession(getString(kw.test.vpncapturedata.R.string.app_name)).setConfigureIntent(null).establish();
        }
    }
}
