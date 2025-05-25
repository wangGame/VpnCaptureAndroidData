package kw.test.vpncapturedata.proxy;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateUtils {
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static X509Certificate generateCertForHost(
            String hostname,
            PublicKey publicKey,
            X509Certificate caCert,
            PrivateKey caKey) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name issuer = new JcaX509CertificateHolder(caCert).getSubject();
        BigInteger serial = BigInteger.valueOf(now);
        Date endDate = new Date(now + 365L * 86400000L);

        X500Name subject = new X500Name("CN=" + hostname);
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer, serial, startDate, endDate, subject, subPubKeyInfo);

        certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        certBuilder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, hostname)));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKey);
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
