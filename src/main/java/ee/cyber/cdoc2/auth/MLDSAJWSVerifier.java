package ee.cyber.cdoc2.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.util.Base64URL;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Set;

/**
 * Minimal JWS verifier for prototype ML-DSA support.
 */
public class MLDSAJWSVerifier extends BaseJWSProvider implements JWSVerifier {

    public static final JWSAlgorithm MLDSA = new JWSAlgorithm("MLDSA");

    private final PublicKey publicKey;

    public MLDSAJWSVerifier(PublicKey publicKey) {
        super(Set.of(MLDSA));
        this.publicKey = publicKey;
    }

    @Override
    public boolean verify(
            JWSHeader header,
            byte[] signingInput,
            Base64URL signature
    ) throws JOSEException {

        if (!supportedJWSAlgorithms().contains(header.getAlgorithm())) {
            throw new JOSEException("Unsupported JWS algorithm: " + header.getAlgorithm());
        }

        try {
            Provider provider = getJCAContext().getProvider();
            Signature verifier = (provider != null)
                    ? Signature.getInstance("MLDSA", provider)
                    : Signature.getInstance("MLDSA");

            verifier.initVerify(publicKey);
            verifier.update(signingInput);
            return verifier.verify(signature.decode());
        } catch (GeneralSecurityException e) {
            throw new JOSEException("ML-DSA verification failed", e);
        }
    }
}

