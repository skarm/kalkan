import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

/** Creates the PKCS12 fixtures used by the Go SDK tests. */
class CreateStore {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new KalkanProvider());
        String provider = KalkanProvider.PROVIDER_NAME;
        byte[] encoded = Files.readAllBytes(Path.of(args[0]));
        PrivateKey key =
                KeyFactory.getInstance("RSA", provider)
                        .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        Arrays.fill(encoded, (byte) 0);

        Certificate cert;
        try (InputStream input = Files.newInputStream(Path.of(args[1]))) {
            cert = CertificateFactory.getInstance("X.509", provider).generateCertificate(input);
        }

        KeyStore store = KeyStore.getInstance("PKCS12", provider);
        store.load(null, null);
        store.setKeyEntry("test", key, "test-password".toCharArray(), new Certificate[] {cert});
        try (OutputStream output = Files.newOutputStream(Path.of(args[2]))) {
            store.store(output, "test-password".toCharArray());
        }
    }
}
