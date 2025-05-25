package kw.test.vpncapturedata.proxy;

import android.content.Context;
import android.os.Build;

import androidx.annotation.RequiresApi;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class CertificateManager {
    private Context context;
    private static CertificateManager certificateManager;
    public CertificateManager(Context context) {
        this.context = context;
        certificateManager = this;
    }

    public static CertificateManager getInstance() {
        return certificateManager;
    }

    public InputStream loadFileFromAssets(String filename) throws IOException {
        return context.getAssets().open(filename);
    }

    // 读取 CA 证书（PEM格式）
    public X509Certificate loadCACert() {
        try (InputStream is = loadFileFromAssets("ca.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(is);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 读取所有字节（兼容低版本）
    private byte[] readAllBytes(InputStream inputStream) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[4096];
        while (true) {
            try {
                if (!((nRead = inputStream.read(data, 0, data.length)) != -1)) break;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }

    public PrivateKey loadCAPrivateKey() {
//        try (InputStream keyInputStream = loadFileFromAssets("ca-key.pem")) {
//            byte[] keyBytes = readAllBytes(keyInputStream);
//
//            // 1. 先用 UTF-8 转字符串（API 19+有StandardCharsets）
//            String keyPem;
//            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {
//                keyPem = new String(keyBytes, StandardCharsets.UTF_8);
//            } else {
//                keyPem = new String(keyBytes, "UTF-8");
//            }
//
//            // 2. 去掉 PEM 包裹头尾和所有空白字符
//            String privateKeyPEM = keyPem
//                    .replace("-----BEGIN PRIVATE KEY-----", "")
//                    .replace("-----END PRIVATE KEY-----", "")
//                    .replaceAll("\\s+", "");
//
//            // 3. Base64 解码，低版本使用 android.util.Base64
//            byte[] decoded;
//            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
//                decoded = java.util.Base64.getDecoder().decode(privateKeyPEM);
//            } else {
//                decoded = android.util.Base64.decode(privateKeyPEM, android.util.Base64.DEFAULT);
//            }
//
//            // 4. 构造私钥
//            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
//            KeyFactory kf = KeyFactory.getInstance("RSA");
//            return kf.generatePrivate(keySpec);
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        } catch (InvalidKeySpecException e) {
//            throw new RuntimeException(e);
//        }
        InputStream is = null; // 你的私钥路径
        try {
            is = context.getAssets().open("ca-key.pem");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        PEMParser pemParser = new PEMParser(new InputStreamReader(is));
        Object object = null;
        try {
            object = pemParser.readObject();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            pemParser.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        if (object instanceof PEMKeyPair) {
            // PKCS#1 格式（BEGIN RSA PRIVATE KEY）
            KeyPair kp = null;
            try {
                kp = converter.getKeyPair((PEMKeyPair) object);
            } catch (PEMException e) {
                throw new RuntimeException(e);
            }
            return kp.getPrivate();
        } else if (object instanceof PrivateKeyInfo) {
            // PKCS#8 格式（BEGIN PRIVATE KEY）
            try {
                return converter.getPrivateKey((PrivateKeyInfo) object);
            } catch (PEMException e) {
                throw new RuntimeException(e);
            }
        } else {
            throw new IllegalArgumentException("不支持的私钥格式");
        }
    }

    public void test(){
        CertificateManager cm = new CertificateManager(context);
        X509Certificate caCert = cm.loadCACert();
        PrivateKey caPrivateKey = cm.loadCAPrivateKey();
    }
}
