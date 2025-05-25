//package kw.test.vpncapturedata.proxy;
//
//import android.util.Log;
//
//import java.io.BufferedReader;
//import java.io.BufferedWriter;
//import java.io.IOException;
//import java.io.InputStreamReader;
//import java.io.OutputStreamWriter;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.KeyStore;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.SecureRandom;
//import java.security.cert.Certificate;
//import java.security.cert.X509Certificate;
//import java.util.Date;
//
//import javax.net.ssl.KeyManagerFactory;
//import javax.net.ssl.SSLContext;
//import javax.net.ssl.SSLServerSocket;
//import javax.net.ssl.SSLServerSocketFactory;
//import javax.net.ssl.SSLSocket;
//
//public class LocalTlsProxy {
//
//    private final X509Certificate caCert;
//    private final PrivateKey caPrivateKey;
//    private SSLServerSocket serverSocket;
//    private volatile boolean running = false;
//
//    public LocalTlsProxy(X509Certificate caCert, PrivateKey caPrivateKey) {
//        this.caCert = caCert;
//        this.caPrivateKey = caPrivateKey;
//    }
//
//    /**
//     * 启动代理服务器（异步线程）
//     * @param port 本地监听端口（如8443）
//     */
//    public void start(final int port) {
//        if (running) return;
//
//        running = true;
//
//        new Thread(() -> {
//            try {
//                KeyPair serverKeyPair = generateRSAKeyPair();
//                PublicKey aPublic = serverKeyPair.getPublic();
//                SSLContext sslContext = createSslContext(serverKeyPair.getPrivate(), generateFakeCert("localhost",aPublic ));
//
//                SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
//                serverSocket = (SSLServerSocket) factory.createServerSocket(port);
//
//                while (running && !Thread.currentThread().isInterrupted()) {
//                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
//                    handleClient(clientSocket);
//                }
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        }, "LocalTlsProxyThread").start();
//    }
//
//    /**
//     * 停止代理服务器
//     */
//    public void stop() {
//        running = false;
//        if (serverSocket != null) {
//            try {
//                serverSocket.close();
//            } catch (IOException ignored) {}
//        }
//    }
//
//    /**
//     * 处理与客户端的TLS连接，读取明文请求
//     */
//    private void handleClient(SSLSocket clientSocket) {
//        new Thread(() -> {
//            try {
//                clientSocket.startHandshake();
//
//                BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
//                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
//
//                // 简单打印明文请求（你也可以进一步解析或转发）
//                String line;
//                while ((line = reader.readLine()) != null && !line.isEmpty()) {
//                    Log.i("LocalTlsProxy", "HTTPS Request Line: " + line);
//                }
//
//                // 响应一个简单的HTTP 200 OK（可根据需求改写）
//                writer.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
//                writer.flush();
//
//                clientSocket.close();
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        }).start();
//    }
//
//    private SSLContext createSslContext(PrivateKey privateKey, X509Certificate fakeServerCert) throws Exception {
//        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//        ks.load(null, null);
//        ks.setKeyEntry("alias", privateKey, "password".toCharArray(), new Certificate[]{fakeServerCert, caCert});
//
//        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
//        kmf.init(ks, "password".toCharArray());
//
//        SSLContext context = SSLContext.getInstance("TLS");
//        context.init(kmf.getKeyManagers(), null, new SecureRandom());
//        return context;
//    }
//
//    private KeyPair generateRSAKeyPair() throws Exception {
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//        keyGen.initialize(2048);
//        return keyGen.generateKeyPair();
//    }
//
////    private X509Certificate generateFakeCert(String host, PublicKey serverPubKey) throws Exception {
////        long now = System.currentTimeMillis();
////        Date from = new Date(now);
////        Date to = new Date(now + 365L * 24 * 60 * 60 * 1000);
////
////        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
////        BigInteger serial = BigInteger.valueOf(now);
////        X500Name subject = new X500Name("CN=" + host);
////
////        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
////                issuer, serial, from, to, subject, serverPubKey
////        );
////
////        GeneralName[] altNames = new GeneralName[]{new GeneralName(GeneralName.dNSName, host)};
////        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(altNames));
////
////        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
////        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
////    }
//
//    // 你可以把加载CA证书私钥的代码放在其他地方，传进构造函数
//}
