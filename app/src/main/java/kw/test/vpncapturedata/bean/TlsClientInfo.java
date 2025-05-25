package kw.test.vpncapturedata.bean;

import javax.net.ssl.SSLSocket;

public class TlsClientInfo {
    public SSLSocket sslSocket;
    public String sniHost;

    public TlsClientInfo(SSLSocket sslSocket, String sniHost) {
        this.sslSocket = sslSocket;
        this.sniHost = sniHost;
    }
}
