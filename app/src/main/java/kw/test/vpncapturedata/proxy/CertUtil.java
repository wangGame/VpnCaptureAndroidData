package kw.test.vpncapturedata.proxy;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public class CertUtil {
    public static X509Certificate generateServerCert(
            String hostname,
            PrivateKey caPrivKey,
            X509Certificate caCert
    ) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair serverKeyPair = keyGen.generateKeyPair();

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now);
        Date notAfter = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1年

        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + hostname);
        BigInteger serial = BigInteger.valueOf(now);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                serverKeyPair.getPublic()
        );

        // 添加 SAN 扩展
        GeneralName[] names = new GeneralName[]{ new GeneralName(GeneralName.dNSName, hostname) };
        certBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(names));

        // 设置为 SSL Server
        certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(caPrivKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static X509Certificate generateFakeCert(X509Certificate caCert, PrivateKey caKey,
                                                   KeyPair serverKeyPair, String hostname) throws Exception {
        long now = System.currentTimeMillis();
        Date from = new Date(now);
        Date to = new Date(now + 365L * 24 * 60 * 60 * 1000);

        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + hostname);
        BigInteger serial = BigInteger.valueOf(now);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, from, to, subject, serverKeyPair.getPublic()
        );

        certBuilder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, hostname))
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(caKey);

        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(signer));
    }

    public static SSLContext createSSLContext(X509Certificate cert, PrivateKey key, X509Certificate ca) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", key, "password".toCharArray(), new Certificate[]{cert, ca});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, "password".toCharArray());

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, null);
        return context;
    }
}
