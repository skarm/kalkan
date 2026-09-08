package kalkan.worker;

import static kalkan.worker.CryptoSupport.CLOCK_SKEW;
import static kalkan.worker.CryptoSupport.PROVIDER;
import static kalkan.worker.CryptoSupport.extensionObject;
import static kalkan.worker.CryptoSupport.requireDigitalSignature;
import static kalkan.worker.CryptoSupport.singleASN1;

import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.DERIA5String;
import kz.gov.pki.kalkan.asn1.DERNull;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.x509.AccessDescription;
import kz.gov.pki.kalkan.asn1.x509.AuthorityInformationAccess;
import kz.gov.pki.kalkan.asn1.x509.GeneralName;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp;
import kz.gov.pki.kalkan.ocsp.CertificateID;
import kz.gov.pki.kalkan.ocsp.OCSPReqGenerator;
import kz.gov.pki.kalkan.ocsp.OCSPResp;
import kz.gov.pki.kalkan.ocsp.RespID;
import kz.gov.pki.kalkan.ocsp.RevokedStatus;
import kz.gov.pki.kalkan.ocsp.SingleResp;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Checks current OCSP evidence, including freshness and responder authorization. */
final class OcspValidation {
    private static final long MAX_AGE_WITHOUT_NEXT_UPDATE = 24 * 60 * 60 * 1000L;
    private static final String AUTHORITY_INFORMATION_ACCESS = "1.3.6.1.5.5.7.1.1";
    private static final String NONCE = "1.3.6.1.5.5.7.48.1.2";
    private static final String NO_CHECK = "1.3.6.1.5.5.7.48.1.5";
    private static final String OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    @FunctionalInterface
    interface PathValidator {
        void validate(
                X509Certificate responder, List<X509Certificate> available, Date validationTime)
                throws Exception;
    }

    private final EvidenceFetcher fetcher;
    private final PathValidator pathValidator;

    OcspValidation(EvidenceFetcher fetcher, PathValidator pathValidator) {
        this.fetcher = fetcher;
        this.pathValidator = pathValidator;
    }

    byte[] check(
            X509Certificate certificate,
            X509Certificate issuer,
            List<X509Certificate> chain,
            String source)
            throws Exception {
        CertificateID expected =
                new CertificateID(
                        CertificateID.HASH_SHA1, issuer, certificate.getSerialNumber(), PROVIDER);
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);

        String url = source.isEmpty() ? responderURL(certificate) : source;
        byte[] encoded = fetcher.fetch("POST", url, request(expected, nonce));
        BasicOCSPResp response = parseResponse(encoded);
        SingleResp status = matchingStatus(response, expected);

        Date now = new Date();
        Date produced = response.getProducedAt();
        requireFreshStatus(status, produced, now);
        requireMatchingNonce(response, nonce);
        requireAuthorizedResponder(response, issuer, chain, now, produced);
        requireGoodStatus(status);
        return encoded;
    }

    private static String responderURL(X509Certificate certificate) throws Exception {
        ASN1Object extension = extensionObject(certificate, AUTHORITY_INFORMATION_ACCESS);
        if (extension != null) {
            AccessDescription[] descriptions =
                    AuthorityInformationAccess.getInstance(extension).getAccessDescriptions();
            for (AccessDescription description : descriptions) {
                GeneralName location = description.getAccessLocation();
                if (AccessDescription.id_ad_ocsp.equals(description.getAccessMethod())
                        && location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    return DERIA5String.getInstance(location.getName()).getString();
                }
            }
        }
        throw new Failure(Failure.CRYPTO_ERROR, "Certificate has no OCSP responder URL");
    }

    private static byte[] request(CertificateID expected, byte[] nonce) throws Exception {
        OCSPReqGenerator generator = new OCSPReqGenerator();
        generator.addRequest(expected);
        Hashtable<DERObjectIdentifier, X509Extension> extensions = new Hashtable<>();
        extensions.put(
                new DERObjectIdentifier(NONCE),
                new X509Extension(
                        false, new DEROctetString(new DEROctetString(nonce).getEncoded("DER"))));
        generator.setRequestExtensions(new X509Extensions(extensions));
        return generator.generate().getEncoded();
    }

    private static BasicOCSPResp parseResponse(byte[] encoded) throws Exception {
        singleASN1(encoded);
        OCSPResp response = new OCSPResp(encoded);
        if (response.getStatus() != 0 || !(response.getResponseObject() instanceof BasicOCSPResp)) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "OCSP responder did not return a successful BasicOCSPResponse");
        }
        BasicOCSPResp basic = (BasicOCSPResp) response.getResponseObject();
        if (basic.getCriticalExtensionOIDs() != null
                && !basic.getCriticalExtensionOIDs().isEmpty()) {
            throw new Failure(
                    Failure.UNSUPPORTED, "Critical OCSP response extensions are unsupported");
        }
        return basic;
    }

    private static SingleResp matchingStatus(BasicOCSPResp response, CertificateID expected)
            throws Failure {
        SingleResp matched = null;
        for (SingleResp status : response.getResponses()) {
            if (!expected.equals(status.getCertID())) {
                continue;
            }
            if (matched != null) {
                throw new Failure(
                        Failure.CRYPTO_ERROR,
                        "OCSP response contains duplicate certificate status entries");
            }
            matched = status;
        }
        if (matched == null) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "OCSP response does not match the requested certificate and issuer");
        }
        if (matched.getCriticalExtensionOIDs() != null
                && !matched.getCriticalExtensionOIDs().isEmpty()) {
            throw new Failure(
                    Failure.UNSUPPORTED,
                    "Critical OCSP single-response extensions are unsupported");
        }
        return matched;
    }

    private static void requireFreshStatus(SingleResp status, Date produced, Date now)
            throws Failure {
        Date updated = status.getThisUpdate();
        Date next = status.getNextUpdate();
        if (updated == null
                || produced == null
                || updated.getTime() > now.getTime() + CLOCK_SKEW
                || produced.getTime() > now.getTime() + CLOCK_SKEW
                || produced.getTime() < updated.getTime() - CLOCK_SKEW) {
            throw new Failure(
                    Failure.CRYPTO_ERROR, "OCSP response has invalid or future status timestamps");
        }
        if (next != null) {
            if (next.before(updated)
                    || next.getTime() < now.getTime() - CLOCK_SKEW
                    || produced.getTime() > next.getTime() + CLOCK_SKEW) {
                throw new Failure(
                        Failure.CRYPTO_ERROR,
                        "OCSP response is expired or has inconsistent nextUpdate");
            }
        } else if (updated.getTime() < now.getTime() - MAX_AGE_WITHOUT_NEXT_UPDATE) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "OCSP response without nextUpdate is older than 24 hours");
        }
    }

    private static void requireMatchingNonce(BasicOCSPResp response, byte[] requestedNonce)
            throws Exception {
        ASN1Object returnedNonce = extensionObject(response, NONCE);
        if (returnedNonce != null
                && !MessageDigest.isEqual(
                        requestedNonce, ASN1OctetString.getInstance(returnedNonce).getOctets())) {
            throw new Failure(
                    Failure.CRYPTO_ERROR, "OCSP response nonce does not match the request");
        }
    }

    private void requireAuthorizedResponder(
            BasicOCSPResp response,
            X509Certificate issuer,
            List<X509Certificate> chain,
            Date now,
            Date produced)
            throws Exception {
        Set<X509Certificate> candidates = responderCandidates(response, issuer);
        Exception lastFailure = null;
        for (X509Certificate candidate : candidates) {
            try {
                if (!responderIDMatches(response, candidate)
                        || !response.verify(candidate.getPublicKey(), PROVIDER)) {
                    continue;
                }
                candidate.checkValidity(now);
                candidate.checkValidity(produced);
                if (!candidate.equals(issuer)) {
                    requireAuthorizedDelegate(candidate, issuer, chain, candidates, now);
                }
                return;
            } catch (Exception rejected) {
                // Renewed certificates can share the responder ID and key. An
                // unusable candidate must not hide another authorized one.
                lastFailure = rejected;
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new Failure(
                Failure.CRYPTO_ERROR,
                "OCSP response signature has no authorized issuer or delegated responder");
    }

    private static Set<X509Certificate> responderCandidates(
            BasicOCSPResp response, X509Certificate issuer) throws Exception {
        Set<X509Certificate> candidates = new LinkedHashSet<>();
        candidates.add(issuer);
        X509Certificate[] embedded = response.getCerts(PROVIDER);
        if (embedded != null) {
            candidates.addAll(Arrays.asList(embedded));
        }
        return candidates;
    }

    private static boolean responderIDMatches(BasicOCSPResp response, X509Certificate certificate)
            throws Exception {
        return response.getResponderId().equals(new RespID(certificate.getSubjectX500Principal()))
                || response.getResponderId().equals(new RespID(certificate.getPublicKey()));
    }

    private void requireAuthorizedDelegate(
            X509Certificate responder,
            X509Certificate issuer,
            List<X509Certificate> chain,
            Set<X509Certificate> candidates,
            Date now)
            throws Exception {
        if (!responder.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "Delegated OCSP responder is not issued by the certificate issuer");
        }
        responder.verify(issuer.getPublicKey(), PROVIDER);
        List<String> usage = responder.getExtendedKeyUsage();
        if (usage == null || !usage.contains(OCSP_SIGNING)) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "Delegated OCSP responder lacks OCSPSigning extended key usage");
        }
        requireDigitalSignature(responder, "OCSP responder");

        List<X509Certificate> pool = new ArrayList<>(chain);
        pool.addAll(candidates);
        pool.add(responder);
        pathValidator.validate(responder, pool, now);

        if (responder.getExtensionValue(NO_CHECK) == null) {
            throw new Failure(
                    Failure.UNSUPPORTED,
                    "Delegated OCSP responder without id-pkix-ocsp-nocheck is unsupported");
        }
        if (!(extensionObject(responder, NO_CHECK) instanceof DERNull)) {
            throw new Failure(Failure.CRYPTO_ERROR, "Invalid OCSP responder nocheck extension");
        }
    }

    private static void requireGoodStatus(SingleResp response) throws Failure {
        Object status = response.getCertStatus();
        if (status instanceof RevokedStatus) {
            throw new Failure(Failure.CRYPTO_ERROR, "Certificate is revoked (OCSP)");
        }
        if (status != null) {
            throw new Failure(Failure.CRYPTO_ERROR, "Certificate status is unknown (OCSP)");
        }
    }
}
