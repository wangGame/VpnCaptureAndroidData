package kw.test.vpncapturedata.proxy;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class MITMProxy {
    private final X509Certificate caCert;
    private final PrivateKey caPrivateKey;

    public MITMProxy(X509Certificate caCert, PrivateKey caPrivateKey) {
        this.caCert = caCert;
        this.caPrivateKey = caPrivateKey;
    }

    public X509Certificate generateFakeCert(String host, PublicKey serverPubKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + host);

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, serverPubKey
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC")
                .build(caPrivateKey);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));
    }


    public SSLSocket createFakeServerSocket(Socket clientSocket, X509Certificate fakeCert, PrivateKey fakeKey) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("alias", fakeKey, "password".toCharArray(), new Certificate[]{fakeCert, caCert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, "password".toCharArray());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) factory.createSocket(
                clientSocket,
                clientSocket.getInetAddress().getHostAddress(),
                clientSocket.getPort(),
                true
        );
        sslSocket.setUseClientMode(false);
        sslSocket.startHandshake();

        return sslSocket;
    }

    public SSLSocket connectToRemoteServer(String host, int port) throws Exception {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket sslSocket = (SSLSocket) factory.createSocket(host, port);
        sslSocket.startHandshake();
        return sslSocket;
    }

    public void forwardData(InputStream in, OutputStream out) {
        new Thread(() -> {
            byte[] buffer = new byte[8192];
            int len;
            try {
                while ((len = in.read(buffer)) != -1) {
                    out.write(buffer, 0, len);
                    out.flush();
                }
            } catch (IOException ignored) {
            }
        }).start();
    }
}
