package kw.test.vpncapturedata.proxy;

import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import kw.test.vpncapturedata.bean.TlsClientInfo;

public class MitmTlsServer {
    private final X509Certificate caCert;
    private final PrivateKey caKey;

    public MitmTlsServer(X509Certificate caCert, PrivateKey caKey) {
        this.caCert = caCert;
        this.caKey = caKey;
    }

    public void start() throws Exception {
        Log.i("chenyikeVPN", "监听本地端口: 8888");
        ServerSocket serverSocket = new ServerSocket(9056);


        while (true) {
            Socket client = serverSocket.accept();
            new Thread(() -> {
                try {
                    TlsClientInfo info = handleTls(client);
                    if (info != null) {
                        relay(info.sslSocket, info.sniHost, 443); // ✅这里终于可以拿到 remoteHost
                    } else {
                        client.close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    try {
                        client.close();
                    } catch (IOException ignored) {}
                }
            }).start();
        }
    }

    public String extractSniFromClientHello(byte[] clientHelloBytes) {
        try {
            int pos = 0;

            // TLS Record Layer
            if (clientHelloBytes[pos++] != 0x16) return null; // handshake record
            // 跳过版本号 (2 bytes)
            pos += 2;
            // 跳过记录长度 (2 bytes)
            int recordLength = ((clientHelloBytes[pos++] & 0xFF) << 8) | (clientHelloBytes[pos++] & 0xFF);

            // Handshake Protocol
            if (clientHelloBytes[pos++] != 0x01) return null; // ClientHello
            // 跳过 handshake length (3 bytes)
            pos += 3;
            // 跳过版本号 (2 bytes)
            pos += 2;
            // 跳过随机数 (32 bytes)
            pos += 32;

            // Session ID
            int sessionIdLength = clientHelloBytes[pos++] & 0xFF;
            pos += sessionIdLength;

            // Cipher Suites
            int cipherSuitesLength = ((clientHelloBytes[pos++] & 0xFF) << 8) | (clientHelloBytes[pos++] & 0xFF);
            pos += cipherSuitesLength;

            // Compression Methods
            int compressionMethodsLength = clientHelloBytes[pos++] & 0xFF;
            pos += compressionMethodsLength;

            // 扩展部分长度
            int extensionsLength = ((clientHelloBytes[pos++] & 0xFF) << 8) | (clientHelloBytes[pos++] & 0xFF);
            int extensionsLimit = pos + extensionsLength;

            while (pos + 4 <= extensionsLimit) {
                int extType = ((clientHelloBytes[pos++] & 0xFF) << 8) | (clientHelloBytes[pos++] & 0xFF);
                int extLen = ((clientHelloBytes[pos++] & 0xFF) << 8) | (clientHelloBytes[pos++] & 0xFF);

                if (extType == 0x00) { // Server Name extension
                    int serverNameListLength = ((clientHelloBytes[pos++] & 0xFF) << 8) | (clientHelloBytes[pos++] & 0xFF);
                    int serverNameType = clientHelloBytes[pos++] & 0xFF;
                    if (serverNameType != 0) return null; // 只处理 host_name 类型
                    int serverNameLen = ((clientHelloBytes[pos++] & 0xFF) << 8) | (clientHelloBytes[pos++] & 0xFF);
                    String sni = new String(clientHelloBytes, pos, serverNameLen);
                    return sni;
                } else {
                    pos += extLen; // 跳过其它扩展
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private TlsClientInfo handleTls(Socket clientSocket) {
        try {
            InputStream clientInput = clientSocket.getInputStream();
            PushbackInputStream pushbackInput = new PushbackInputStream(clientInput, 1024);

            byte[] clientHello = new byte[1024];
            int len = pushbackInput.read(clientHello);
            if (len == -1) return null;
            pushbackInput.unread(clientHello, 0, len);

            String sniHost = extractSniFromClientHello(Arrays.copyOf(clientHello, len));
            if (sniHost == null) {
                Log.e("MITM", "无法提取 SNI");
                return null;
            }

            Log.i("MITM", "提取 SNI: " + sniHost);

            // 生成伪造证书
            KeyPair serverKeyPair = CertificateUtils.generateRSAKeyPair();
            X509Certificate forgedCert = CertificateUtils.generateCertForHost(
                    sniHost, serverKeyPair.getPublic(), caCert, caKey);

            // 构造 KeyStore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, null);
            ks.setKeyEntry("alias", serverKeyPair.getPrivate(), "password".toCharArray(),
                    new Certificate[]{forgedCert, caCert});

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "password".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);

            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(
                    clientSocket,
                    clientSocket.getInetAddress().getHostAddress(),
                    clientSocket.getPort(),
                    true);
            sslSocket.setUseClientMode(false);
            sslSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            sslSocket.startHandshake();

            return new TlsClientInfo(sslSocket, sniHost);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void relay(SSLSocket clientSocket, String remoteHost, int remotePort) {
        Socket serverSocket = null;
        try {
            serverSocket = new Socket(remoteHost, remotePort);

            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();

            InputStream serverIn = serverSocket.getInputStream();
            OutputStream serverOut = serverSocket.getOutputStream();

            Thread clientToServer = new Thread(() -> {
                try {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = clientIn.read(buffer)) != -1) {
                        serverOut.write(buffer, 0, read);
                        serverOut.flush();
                        String msg = new String(buffer, 0, read, StandardCharsets.UTF_8);
                        Log.i("VPN","========================>  "+msg);
                    }
                } catch (IOException e) {
                } finally {
                    try {
                        serverOut.close();
                    } catch (IOException ignored) {
                    }
                }
            });
            clientToServer.start();

            Thread serverToClient = new Thread(() -> {
                try {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = serverIn.read(buffer)) != -1) {
                        clientOut.write(buffer, 0, read);
                        clientOut.flush();
                    }
                } catch (IOException e) {
                } finally {
                    try {
                        clientOut.close();
                    } catch (IOException ignored) {
                    }
                }
            });
            serverToClient.start();

            clientToServer.join();
            serverToClient.join();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (serverSocket != null) serverSocket.close();
            } catch (IOException ignored) {
            }
            try {
                if (clientSocket != null) clientSocket.close();
            } catch (IOException ignored) {
            }
        }
    }
}