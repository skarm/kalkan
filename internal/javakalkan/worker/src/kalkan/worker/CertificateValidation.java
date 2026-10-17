package kalkan.worker;

import static kalkan.worker.Arguments.utf8;
import static kalkan.worker.CryptoSupport.EMPTY;
import static kalkan.worker.CryptoSupport.PROVIDER;

import kz.gov.pki.kalkan.x509.ExtendedPKIXBuilderParameters;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Owns trusted certificates, PKIX paths and the session's explicit revocation policy. */
final class CertificateValidation {
    private static final int AUTO_ROLE = 0;
    private static final int ROOT_ROLE = 0x201;
    private static final int INTERMEDIATE_ROLE = 0x202;
    private static final int USER_ROLE = 0x204;

    record Request(
            byte[] encoded,
            String revocationMode,
            String revocationSource,
            byte[] localCRLs,
            boolean skipTime,
            Date checkTime,
            boolean returnOCSP) {}

    private record RevocationPolicy(
            String mode, String source, List<X509CRL> localCRLs, Date checkTime) {
        static RevocationPolicy create(String mode, String source, byte[] crls, Date checkTime)
                throws Exception {
            if (!mode.equals("ocsp") && !mode.equals("crl") && !mode.equals("none")) {
                throw new Failure(Failure.INVALID_ARGUMENT, "Unknown revocation mode");
            }
            if (!mode.equals("crl") && crls.length != 0) {
                throw new Failure(Failure.INVALID_ARGUMENT, "Local CRLs require CRL mode");
            }
            if (mode.equals("none") && !source.isEmpty()) {
                throw new Failure(
                        Failure.INVALID_ARGUMENT, "Disabled revocation cannot have a source");
            }
            if (!source.isEmpty() && crls.length != 0) {
                throw new Failure(
                        Failure.INVALID_ARGUMENT, "Choose either a CRL URL or local CRLs");
            }
            List<X509CRL> parsed =
                    crls.length == 0 ? Collections.emptyList() : CrlValidation.parse(crls);
            return new RevocationPolicy(mode, source, parsed, checkTime);
        }
    }

    private final KeyStoreState keys;
    private final OcspValidation ocsp;
    private final CrlValidation crl;
    private final Set<X509Certificate> roots = new LinkedHashSet<>();
    private final Set<X509Certificate> certificates = new LinkedHashSet<>();
    private final Map<String, byte[]> verifiedRevocation = new HashMap<>();
    private RevocationPolicy revocation =
            new RevocationPolicy("ocsp", "", Collections.emptyList(), null);

    CertificateValidation(KeyStoreState keys, EvidenceFetcher fetcher) {
        this.keys = keys;
        this.ocsp =
                new OcspValidation(
                        fetcher,
                        (responder, available, validationTime) ->
                                validateChain(
                                        responder,
                                        available,
                                        false,
                                        validationTime,
                                        "OCSP responder certificate"));
        this.crl = new CrlValidation(fetcher);
    }

    void beginOperation() {
        verifiedRevocation.clear();
    }

    void clear() {
        roots.clear();
        certificates.clear();
        verifiedRevocation.clear();
    }

    List<X509Certificate> availableCertificates() throws Exception {
        Set<X509Certificate> result = new LinkedHashSet<>(certificates);
        result.addAll(roots);
        keys.addCertificates(result);
        return new ArrayList<>(result);
    }

    void loadTrust(byte[] encoded, int role) throws Exception {
        if (role != AUTO_ROLE
                && role != ROOT_ROLE
                && role != INTERMEDIATE_ROLE
                && role != USER_ROLE) {
            throw new Failure(Failure.INVALID_ARGUMENT, "Unsupported certificate role");
        }
        X509Certificate certificate = parseCertificate(encoded);
        int resolvedRole = role == AUTO_ROLE ? detectRole(certificate) : role;
        if (resolvedRole == ROOT_ROLE || resolvedRole == INTERMEDIATE_ROLE) {
            requireCertificateAuthority(certificate);
        }
        if (resolvedRole == ROOT_ROLE) {
            roots.add(certificate);
        } else {
            certificates.add(certificate);
        }
    }

    private static X509Certificate parseCertificate(byte[] encoded) throws Exception {
        ByteArrayInputStream input = new ByteArrayInputStream(encoded);
        X509Certificate certificate =
                (X509Certificate)
                        CertificateFactory.getInstance("X.509", PROVIDER)
                                .generateCertificate(input);
        if (input.available() != 0) {
            throw new Failure(Failure.INVALID_ARGUMENT, "Certificate input has trailing data");
        }
        return certificate;
    }

    private static int detectRole(X509Certificate certificate) throws Exception {
        if (certificate.getBasicConstraints() < 0) {
            return USER_ROLE;
        }
        if (certificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())) {
            try {
                certificate.verify(certificate.getPublicKey(), PROVIDER);
                return ROOT_ROLE;
            } catch (GeneralSecurityException ignored) {
                // A self-issued certificate is a root only if its self-signature verifies.
            }
        }
        return INTERMEDIATE_ROLE;
    }

    private static void requireCertificateAuthority(X509Certificate certificate) throws Failure {
        if (certificate.getBasicConstraints() < 0) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT,
                    "CA certificate must have the basic constraints CA flag");
        }
        boolean[] usage = certificate.getKeyUsage();
        if (usage != null && (usage.length < 6 || !usage[5])) {
            throw new Failure(
                    Failure.INVALID_ARGUMENT, "CA certificate does not permit certificate signing");
        }
    }

    void configureRevocation(String mode, String source, byte[] crls) throws Exception {
        revocation = RevocationPolicy.create(mode, source, crls, revocation.checkTime());
    }

    String revocationDiagnostic() {
        if (revocation.mode().equals("none")) {
            return "explicitly disabled";
        }
        return revocation.mode()
                + (revocation.checkTime() == null
                        ? " OK (current status)"
                        : " OK (at requested time)");
    }

    byte[][] validateCertificate(Request request) throws Exception {
        if (request.checkTime() != null && request.revocationMode().equals("ocsp")) {
            throw new Failure(
                    Failure.UNSUPPORTED,
                    "Historical OCSP validation requires archived evidence and is unsupported");
        }
        if (request.returnOCSP() && !request.revocationMode().equals("ocsp")) {
            throw new Failure(Failure.INVALID_ARGUMENT, "OCSP response output requires OCSP mode");
        }

        RevocationPolicy previous = revocation;
        try {
            revocation =
                    RevocationPolicy.create(
                            request.revocationMode(),
                            request.revocationSource(),
                            request.localCRLs(),
                            request.checkTime());
            return validateWithPolicy(request);
        } finally {
            revocation = previous;
        }
    }

    private byte[][] validateWithPolicy(Request request) throws Exception {
        X509Certificate certificate = parseCertificate(request.encoded());
        // An explicit CheckTime takes precedence over SkipCertificateTimeCheck.
        boolean skipTime = request.skipTime() && request.checkTime() == null;
        Date validationTime = request.checkTime() == null ? new Date() : request.checkTime();
        if (!skipTime) {
            certificate.checkValidity(validationTime);
        }
        List<X509Certificate> pool = availableCertificates();
        pool.add(certificate);
        List<X509Certificate> chain =
                validateChain(certificate, pool, skipTime, validationTime, "Certificate");
        byte[] leafOCSP = checkRevocation(chain);
        String diagnostic =
                "Certificate validation - OK; trust chain=OK; certificate time="
                        + (skipTime ? "skipped" : "checked")
                        + "; revocation="
                        + revocationDiagnostic();
        return new byte[][] {utf8(diagnostic), request.returnOCSP() ? leafOCSP : EMPTY};
    }

    byte[] checkRevocation(List<X509Certificate> chain) throws Exception {
        byte[] leafOCSP = EMPTY;
        if (revocation.mode().equals("none")) {
            return leafOCSP;
        }
        for (int index = 0; index + 1 < chain.size(); index++) {
            X509Certificate certificate = chain.get(index);
            X509Certificate issuer = chain.get(index + 1);
            String key = fingerprint(certificate) + ":" + fingerprint(issuer);
            byte[] result = verifiedRevocation.get(key);
            if (result == null) {
                if (revocation.mode().equals("ocsp")) {
                    result = ocsp.check(certificate, issuer, chain, revocation.source());
                } else {
                    crl.check(
                            certificate,
                            issuer,
                            revocation.source(),
                            revocation.localCRLs(),
                            revocation.checkTime());
                    result = EMPTY;
                }
                verifiedRevocation.put(key, result);
            }
            if (index == 0) {
                leafOCSP = result;
            }
        }
        return leafOCSP;
    }

    private static String fingerprint(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        return Base64.getEncoder().encodeToString(digest);
    }

    List<X509Certificate> validateChain(
            X509Certificate signer,
            List<X509Certificate> available,
            boolean skipTime,
            Date validationTime,
            String purpose)
            throws Exception {
        Set<TrustAnchor> anchors = trustAnchors(skipTime, validationTime);
        ExtendedPKIXBuilderParameters parameters =
                pathParameters(signer, available, anchors, skipTime, validationTime);
        try {
            PKIXCertPathBuilderResult result =
                    (PKIXCertPathBuilderResult)
                            CertPathBuilder.getInstance("PKIX", PROVIDER).build(parameters);
            return certificatesInChain(result);
        } catch (CertPathBuilderException exception) {
            throw new Failure(
                    Failure.CRYPTO_ERROR, purpose + " does not chain to a loaded trusted CA");
        }
    }

    private Set<TrustAnchor> trustAnchors(boolean skipTime, Date validationTime) throws Exception {
        if (roots.isEmpty()) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "No trusted CA is loaded; configure a trusted root certificate");
        }
        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate root : roots) {
            if (!skipTime) {
                try {
                    root.checkValidity(validationTime);
                } catch (CertificateExpiredException | CertificateNotYetValidException ignored) {
                    continue;
                }
            }
            anchors.add(new TrustAnchor(root, null));
        }
        if (anchors.isEmpty()) {
            throw new Failure(Failure.CRYPTO_ERROR, "No loaded trusted CA is currently valid");
        }
        return anchors;
    }

    private static ExtendedPKIXBuilderParameters pathParameters(
            X509Certificate signer,
            List<X509Certificate> available,
            Set<TrustAnchor> anchors,
            boolean skipTime,
            Date validationTime)
            throws Exception {
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(signer);
        PKIXBuilderParameters base = new PKIXBuilderParameters(anchors, selector);
        List<X509Certificate> pool = new ArrayList<>();
        for (X509Certificate certificate : available) {
            pool.add(skipTime ? new CertificateWithoutTimeCheck(certificate) : certificate);
        }
        base.addCertStore(
                CertStore.getInstance(
                        "Collection", new CollectionCertStoreParameters(pool), PROVIDER));
        base.setRevocationEnabled(false);
        base.setSigProvider(PROVIDER);
        base.setDate(validationTime);
        ExtendedPKIXBuilderParameters parameters =
                (ExtendedPKIXBuilderParameters) ExtendedPKIXBuilderParameters.getInstance(base);
        parameters.setAdditionalLocationsEnabled(false);
        return parameters;
    }

    private static List<X509Certificate> certificatesInChain(PKIXCertPathBuilderResult result) {
        List<X509Certificate> chain = new ArrayList<>();
        for (Certificate value : result.getCertPath().getCertificates()) {
            X509Certificate certificate = (X509Certificate) value;
            chain.add(
                    certificate instanceof CertificateWithoutTimeCheck wrapper
                            ? wrapper.unwrap()
                            : certificate);
        }
        chain.add(result.getTrustAnchor().getTrustedCert());
        return chain;
    }
}
