import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class GenerateMldsaTestCerts {

    private static final String KEYGEN_ALG = "ML-DSA";
    private static final MLDSAParameterSpec PARAM_SPEC = MLDSAParameterSpec.ml_dsa_65;
    private static final String CERT_SIG_ALG = "ML-DSA-65";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair caKeyPair = generateMldsaKeyPair();
        X509Certificate caCert = generateSelfSignedCaCert(
                caKeyPair,
                "C=EE, O=Cybernetica AS, CN=ML-DSA Test CA"
        );

        KeyPair leafKeyPair = generateMldsaKeyPair();
        X509Certificate leafCert = generateLeafCert(
                leafKeyPair,
                caKeyPair,
                caCert,
                "SERIALNUMBER=PNOEE-30303039914, GIVENNAME=TESTNUMBER, SURNAME=OK, CN=TESTNUMBER OK, C=EE"
        );

        writePem("mldsa-ca-cert.pem", caCert);
        writePem("mldsa-leaf-cert.pem", leafCert);
        writePem("mldsa-leaf-key.pem", leafKeyPair.getPrivate());

        System.out.println("Generated:");
        System.out.println("  mldsa-ca-cert.pem");
        System.out.println("  mldsa-leaf-cert.pem");
        System.out.println("  mldsa-leaf-key.pem");
    }

    private static KeyPair generateMldsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEYGEN_ALG, "BC");
        kpg.initialize(PARAM_SPEC);
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateSelfSignedCaCert(
            KeyPair caKeyPair,
            String subjectDn
    ) throws Exception {
        X500Name subject = new X500Name(subjectDn);
        Instant now = Instant.now();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(3650, ChronoUnit.DAYS)),
                subject,
                caKeyPair.getPublic()
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
        );
        certBuilder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(caKeyPair.getPublic())
        );
        certBuilder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caKeyPair.getPublic())
        );

        ContentSigner signer = new JcaContentSignerBuilder(CERT_SIG_ALG)
                .setProvider("BC")
                .build(caKeyPair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

    private static X509Certificate generateLeafCert(
            KeyPair leafKeyPair,
            KeyPair caKeyPair,
            X509Certificate caCert,
            String subjectDn
    ) throws Exception {
        X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        X500Name subject = new X500Name(subjectDn);
        Instant now = Instant.now();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis() + 1),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                leafKeyPair.getPublic()
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature)
        );
        certBuilder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(leafKeyPair.getPublic())
        );
        certBuilder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caKeyPair.getPublic())
        );

        ContentSigner signer = new JcaContentSignerBuilder(CERT_SIG_ALG)
                .setProvider("BC")
                .build(caKeyPair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

    private static void writePem(String fileName, Object obj) throws Exception {
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(fileName))) {
            writer.writeObject(obj);
        }
    }
}

