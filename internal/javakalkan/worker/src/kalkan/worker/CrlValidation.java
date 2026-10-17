package kalkan.worker;

import static kalkan.worker.CryptoSupport.CLOCK_SKEW;
import static kalkan.worker.CryptoSupport.EMPTY;
import static kalkan.worker.CryptoSupport.PROVIDER;
import static kalkan.worker.CryptoSupport.extensionObject;

import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.DERIA5String;
import kz.gov.pki.kalkan.asn1.DERInteger;
import kz.gov.pki.kalkan.asn1.x509.AuthorityKeyIdentifier;
import kz.gov.pki.kalkan.asn1.x509.CRLDistPoint;
import kz.gov.pki.kalkan.asn1.x509.DistributionPoint;
import kz.gov.pki.kalkan.asn1.x509.DistributionPointName;
import kz.gov.pki.kalkan.asn1.x509.GeneralName;
import kz.gov.pki.kalkan.asn1.x509.GeneralNames;
import kz.gov.pki.kalkan.asn1.x509.SubjectKeyIdentifier;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

/** Authenticates full direct CRLs and selects the newest unambiguous publication. */
final class CrlValidation {
    private static final String DISTRIBUTION_POINTS = "2.5.29.31";
    private static final String DELTA_CRL_INDICATOR = "2.5.29.27";
    private static final String ISSUING_DISTRIBUTION_POINT = "2.5.29.28";
    private static final String AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    private static final String SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
    private static final String CERTIFICATE_ISSUER = "2.5.29.29";
    private static final String CRL_NUMBER = "2.5.29.20";

    private final EvidenceFetcher fetcher;

    CrlValidation(EvidenceFetcher fetcher) {
        this.fetcher = fetcher;
    }

    static List<X509CRL> parse(byte[] encoded) throws Exception {
        Collection<? extends CRL> parsed =
                CertificateFactory.getInstance("X.509", PROVIDER)
                        .generateCRLs(new ByteArrayInputStream(encoded));
        List<X509CRL> result = new ArrayList<>();
        for (CRL crl : parsed) {
            if (!(crl instanceof X509CRL x509)) {
                throw new Failure(Failure.INVALID_ARGUMENT, "Only X509 CRLs are supported");
            }
            result.add(x509);
        }
        if (result.isEmpty()) {
            throw new Failure(Failure.INVALID_ARGUMENT, "CRL input contains no revocation list");
        }
        return result;
    }

    void check(
            X509Certificate certificate,
            X509Certificate issuer,
            String source,
            List<X509CRL> localCRLs,
            Date checkTime)
            throws Exception {
        // CRL scope restrictions apply to every source, including explicit URLs and local bundles.
        requireDirectDistributionPoints(certificate);
        requireCRLSigning(issuer);

        List<X509CRL> candidates = localCRLs;
        if (candidates.isEmpty()) {
            String url = source.isEmpty() ? distributionPointURL(certificate) : source;
            candidates = parse(fetcher.fetch("GET", url, EMPTY));
        }

        X509CRL newest = selectNewest(candidates, issuer, checkTime);
        X509CRLEntry revoked = newest.getRevokedCertificate(certificate.getSerialNumber());
        if (revoked != null
                && (checkTime == null || !revoked.getRevocationDate().after(checkTime))) {
            throw new Failure(Failure.CRYPTO_ERROR, "Certificate is revoked (CRL)");
        }
    }

    private static void requireCRLSigning(X509Certificate issuer) throws Failure {
        boolean[] usage = issuer.getKeyUsage();
        if (usage != null && (usage.length < 7 || !usage[6])) {
            throw new Failure(
                    Failure.CRYPTO_ERROR, "CRL issuer certificate does not permit CRL signing");
        }
    }

    private static DistributionPoint[] distributionPoints(X509Certificate certificate)
            throws Exception {
        ASN1Object extension = extensionObject(certificate, DISTRIBUTION_POINTS);
        if (extension == null) {
            return new DistributionPoint[0];
        }
        return CRLDistPoint.getInstance(extension).getDistributionPoints();
    }

    private static void requireDirectDistributionPoints(X509Certificate certificate)
            throws Exception {
        for (DistributionPoint point : distributionPoints(certificate)) {
            if (point.getCRLIssuer() != null || point.getReasons() != null) {
                throw new Failure(
                        Failure.UNSUPPORTED,
                        "Indirect or reason-partitioned CRL distribution points are unsupported");
            }
        }
    }

    private static String distributionPointURL(X509Certificate certificate) throws Exception {
        requireDirectDistributionPoints(certificate);
        for (DistributionPoint point : distributionPoints(certificate)) {
            DistributionPointName name = point.getDistributionPoint();
            if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                continue;
            }
            for (GeneralName general : GeneralNames.getInstance(name.getName()).getNames()) {
                if (general.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    return DERIA5String.getInstance(general.getName()).getString();
                }
            }
        }
        throw new Failure(
                Failure.CRYPTO_ERROR, "Certificate has no supported CRL distribution point");
    }

    private static X509CRL selectNewest(
            List<X509CRL> candidates, X509Certificate issuer, Date checkTime) throws Exception {
        X509CRL newest = null;
        for (X509CRL candidate : candidates) {
            if (!candidate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                continue;
            }
            Date validationTime = checkTime == null ? new Date() : checkTime;
            if (!isCurrent(candidate, validationTime) || !hasValidSignature(candidate, issuer)) {
                continue;
            }

            requireSupportedScope(candidate);
            requireIssuerKeyIdentifier(candidate, issuer);
            requireSupportedEntries(candidate);
            if (newest == null || isNewer(candidate, newest)) {
                newest = candidate;
            }
        }
        if (newest == null) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "No current authenticated full CRL matches the certificate issuer");
        }
        return newest;
    }

    private static boolean isCurrent(X509CRL crl, Date validationTime) {
        Date updated = crl.getThisUpdate();
        Date next = crl.getNextUpdate();
        return updated != null
                && next != null
                && updated.getTime() <= validationTime.getTime() + CLOCK_SKEW
                && next.getTime() >= validationTime.getTime() - CLOCK_SKEW
                && !next.before(updated);
    }

    private static boolean hasValidSignature(X509CRL crl, X509Certificate issuer) throws Exception {
        try {
            crl.verify(issuer.getPublicKey(), PROVIDER);
            return true;
        } catch (SignatureException | InvalidKeyException ignored) {
            return false;
        }
    }

    private static void requireSupportedScope(X509CRL crl) throws Failure {
        if (crl.getExtensionValue(DELTA_CRL_INDICATOR) != null
                || crl.getExtensionValue(ISSUING_DISTRIBUTION_POINT) != null) {
            throw new Failure(
                    Failure.UNSUPPORTED,
                    "Delta, indirect and scoped CRLs are unsupported; provide a full direct CRL");
        }
        if (crl.hasUnsupportedCriticalExtension()) {
            throw new Failure(Failure.UNSUPPORTED, "CRL has an unsupported critical extension");
        }
    }

    private static void requireIssuerKeyIdentifier(X509CRL crl, X509Certificate issuer)
            throws Exception {
        ASN1Object authorityExtension = extensionObject(crl, AUTHORITY_KEY_IDENTIFIER);
        ASN1Object subjectExtension = extensionObject(issuer, SUBJECT_KEY_IDENTIFIER);
        if (authorityExtension == null || subjectExtension == null) {
            return;
        }
        byte[] authority =
                AuthorityKeyIdentifier.getInstance(authorityExtension).getKeyIdentifier();
        if (authority != null
                && !MessageDigest.isEqual(
                        authority,
                        SubjectKeyIdentifier.getInstance(subjectExtension).getKeyIdentifier())) {
            throw new Failure(
                    Failure.CRYPTO_ERROR, "CRL authority key identifier does not match its issuer");
        }
    }

    private static void requireSupportedEntries(X509CRL crl) throws Failure {
        Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
        if (entries == null) {
            return;
        }
        for (X509CRLEntry entry : entries) {
            if (entry.getExtensionValue(CERTIFICATE_ISSUER) != null
                    || entry.getCertificateIssuer() != null) {
                throw new Failure(Failure.UNSUPPORTED, "Indirect CRL entries are unsupported");
            }
            if (entry.hasUnsupportedCriticalExtension()) {
                throw new Failure(
                        Failure.UNSUPPORTED, "CRL entry has an unsupported critical extension");
            }
        }
    }

    private static BigInteger number(X509CRL crl) throws Exception {
        ASN1Object value = extensionObject(crl, CRL_NUMBER);
        if (value == null) {
            return null;
        }
        if (!(value instanceof DERInteger number) || number.getValue().signum() < 0) {
            throw new Failure(Failure.CRYPTO_ERROR, "CRL number must be a nonnegative integer");
        }
        return number.getValue();
    }

    private static boolean isNewer(X509CRL candidate, X509CRL previous) throws Exception {
        if (Arrays.equals(candidate.getTBSCertList(), previous.getTBSCertList())) {
            return false;
        }
        BigInteger candidateNumber = number(candidate);
        BigInteger previousNumber = number(previous);
        int timeOrder = candidate.getThisUpdate().compareTo(previous.getThisUpdate());
        if (candidateNumber != null && previousNumber != null) {
            int numberOrder = candidateNumber.compareTo(previousNumber);
            if (numberOrder == 0
                    || (timeOrder != 0
                            && Integer.signum(timeOrder) != Integer.signum(numberOrder))) {
                throw new Failure(
                        Failure.CRYPTO_ERROR, "CRLs have conflicting numbers or publication times");
            }
            return numberOrder > 0;
        }
        if (timeOrder == 0) {
            throw new Failure(
                    Failure.CRYPTO_ERROR,
                    "Conflicting CRLs have the same publication time and no comparable numbers");
        }
        return timeOrder > 0;
    }
}
