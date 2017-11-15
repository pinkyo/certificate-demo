package my.pinkyo.demo.certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

public class CertificateGenerator {
    private KeyPair keyPair;

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public X509Certificate generateX509Certificate() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // generateX509Certificate EC key pair
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime192v1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", "BC");
        generator.initialize(ecGenSpec, new SecureRandom());
        KeyPair kp = generator.genKeyPair();

        // 1 day ago
        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        // 1 year later
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);

        // create x.509 certificate build
        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=Test"),
                BigInteger.valueOf(System.currentTimeMillis()),
                startDate, endDate,
                new X500Principal("CN=Test"),
                kp.getPublic());

        // Content Signer
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC").build(kp.getPrivate());

        // build x.509 certificate
        X509CertificateHolder holder = v3CertGen.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(holder);

        keyPair = kp;
        return certificate;
    }

    public static String writeCertificateToString(Certificate certificate) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new PrintWriter(bos));
        jcaPEMWriter.writeObject(certificate);
        jcaPEMWriter.flush();

        return bos.toString();
    }

    public void verifySignature(Certificate certificate) throws Exception {
        X509CertificateHolder certHolder = new X509CertificateHolder(certificate.getEncoded());
        // public key from issuer, used to verify signature
        PublicKey publicKey = keyPair.getPublic();
        ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider("BC").build(publicKey);

        if (!certHolder.isSignatureValid(contentVerifierProvider)) {
            System.err.println("signature invalid");
        } else {
            System.out.printf("signature valid");
        }
    }

    public static void loadKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream("C:\\Users\\yinkn\\Documents\\GitHub\\certificate-demo\\src\\main\\resources\\test.jks"), "password".toCharArray());
        Certificate certificate = keyStore.getCertificate("test");
        System.out.println(certificate);
    }


    public static void main(String[] args) throws Exception {
        CertificateGenerator generator = new CertificateGenerator();
        X509Certificate x509Certificate = generator.generateX509Certificate();

        //write certificate to string
        System.out.println(CertificateGenerator.writeCertificateToString(x509Certificate));

        generator.verifySignature(x509Certificate);
    }
}
