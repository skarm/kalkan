package kalkan.worker;

import static kalkan.worker.CryptoSupport.PROVIDER;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Private keys and their certificate chains; loading keys does not mutate trust. */
final class KeyStoreState {
    private final Map<String, KeyEntry> keys = new LinkedHashMap<>();
    private String defaultAlias;

    static final class KeyEntry {
        final PrivateKey key;
        final X509Certificate certificate;
        final List<X509Certificate> chain;

        KeyEntry(PrivateKey key, X509Certificate certificate, List<X509Certificate> chain) {
            this.key = key;
            this.certificate = certificate;
            this.chain = chain;
        }
    }

    void loadKeyStore(String path, byte[] passwordBytes, String requestedAlias) throws Exception {
        char[] password =
                StandardCharsets.UTF_8
                        .decode(ByteBuffer.wrap(passwordBytes))
                        .toString()
                        .toCharArray();
        try {
            KeyStore store = KeyStore.getInstance("PKCS12", PROVIDER);
            try (InputStream input = Files.newInputStream(Path.of(path))) {
                store.load(input, password);
            }

            Map<String, KeyEntry> loaded = readKeys(store, password);
            String chosen = selectAlias(loaded, requestedAlias);
            if (!requestedAlias.isEmpty() && !loaded.containsKey(requestedAlias)) {
                loaded.put(requestedAlias, loaded.get(chosen));
            }

            keys.clear();
            keys.putAll(loaded);
            defaultAlias = requestedAlias.isEmpty() ? chosen : requestedAlias;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static Map<String, KeyEntry> readKeys(KeyStore store, char[] password)
            throws Exception {
        Map<String, KeyEntry> loaded = new LinkedHashMap<>();
        for (String alias : Collections.list(store.aliases())) {
            if (!store.isKeyEntry(alias)) {
                continue;
            }

            Key key = store.getKey(alias, password);
            Certificate certificate = store.getCertificate(alias);
            if (!(key instanceof PrivateKey privateKey)
                    || !(certificate instanceof X509Certificate signingCertificate)) {
                continue;
            }

            List<X509Certificate> chain = readChain(store.getCertificateChain(alias));
            loaded.put(alias, new KeyEntry(privateKey, signingCertificate, chain));
        }
        return loaded;
    }

    private static List<X509Certificate> readChain(Certificate[] certificates) {
        List<X509Certificate> chain = new ArrayList<>();
        if (certificates != null) {
            for (Certificate certificate : certificates) {
                if (certificate instanceof X509Certificate x509) {
                    chain.add(x509);
                }
            }
        }
        return chain;
    }

    private static String selectAlias(Map<String, KeyEntry> loaded, String requestedAlias)
            throws Failure {
        if (loaded.isEmpty()) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT,
                    "PKCS12 contains no usable private key and certificate");
        }
        if (loaded.size() > 1 && !loaded.containsKey(requestedAlias)) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT,
                    "PKCS12 contains multiple keys; select an existing alias");
        }
        return loaded.containsKey(requestedAlias)
                ? requestedAlias
                : loaded.keySet().iterator().next();
    }

    KeyEntry key(String alias) throws Failure {
        KeyEntry entry = keys.get(alias.isEmpty() ? defaultAlias : alias);
        if (entry == null) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT, "No private key is loaded for the requested alias");
        }
        return entry;
    }

    void clear() {
        keys.clear();
        defaultAlias = null;
    }

    void addCertificates(Set<X509Certificate> result) {
        for (KeyEntry entry : keys.values()) {
            result.add(entry.certificate);
            result.addAll(entry.chain);
        }
    }
}
