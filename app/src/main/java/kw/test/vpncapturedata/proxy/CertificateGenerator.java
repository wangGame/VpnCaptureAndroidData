package kw.test.vpncapturedata.proxy;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateGenerator {
    public static X509Certificate generateCert(String cn, PublicKey serverPublicKey,
                                               X509Certificate caCert, PrivateKey caKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000L * 60 * 60);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * 365);
        BigInteger serial = BigInteger.valueOf(now);

        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + cn);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, serverPublicKey);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(serverPublicKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(caKey);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));
    }
}