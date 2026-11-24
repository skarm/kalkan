package kalkan.worker;

import static kalkan.worker.CryptoSupport.CLOCK_SKEW;
import static kalkan.worker.CryptoSupport.PROVIDER;
import static kalkan.worker.CryptoSupport.requireDigitalSignature;
import static kalkan.worker.CryptoSupport.singleASN1;
import static kalkan.worker.Failure.CRYPTO_ERROR;
import static kalkan.worker.Failure.INVALID_ARGUMENT;
import static kalkan.worker.Failure.UNSUPPORTED;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1Sequence;
import kz.gov.pki.kalkan.asn1.DERInteger;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.x509.GeneralName;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedGenerator;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.tsp.TimeStampRequest;
import kz.gov.pki.kalkan.tsp.TimeStampRequestGenerator;
import kz.gov.pki.kalkan.tsp.TimeStampResponse;
import kz.gov.pki.kalkan.tsp.TimeStampToken;
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/** RFC 3161 requests and authenticated signature timestamp tokens. */
final class TimestampOperations {
    private static final String TIMESTAMPING_EKU = "1.3.6.1.5.5.7.3.8";
    private static final String EXTENDED_KEY_USAGE = "2.5.29.37";
    private static final DERObjectIdentifier SIGNATURE_TIMESTAMP =
            new DERObjectIdentifier("1.2.840.113549.1.9.16.2.14");
    private static final DERObjectIdentifier SIGNING_CERTIFICATE =
            new DERObjectIdentifier("1.2.840.113549.1.9.16.2.12");
    private static final DERObjectIdentifier SIGNING_CERTIFICATE_V2 =
            new DERObjectIdentifier("1.2.840.113549.1.9.16.2.47");

    private final CertificateValidation validation;
    private final EvidenceFetcher transport;
    private String authorityURL = "";

    TimestampOperations(CertificateValidation validation, EvidenceFetcher transport) {
        this.validation = validation;
        this.transport = transport;
    }

    void setAuthorityURL(String url) {
        authorityURL = url;
    }

    Attribute createTimestampAttribute(byte[] signature) throws Exception {
        TimeStampToken token = requestTimestamp(signature);
        ContentInfo content = ContentInfo.getInstance(singleASN1(token.getEncoded()));
        return new Attribute(SIGNATURE_TIMESTAMP, new DERSet(content));
    }

    int validateTimestamps(SignerInformation signer, List<X509Certificate> available)
            throws Exception {
        List<TimeStampToken> tokens = timestampTokens(signer);
        for (TimeStampToken token : tokens) {
            validateTimestamp(token, signer.getSignature(), available);
        }
        return tokens.size();
    }

    Date earliestVerifiedTimestamp(SignerInformation signer, List<X509Certificate> available)
            throws Exception {
        List<TimeStampToken> tokens = timestampTokens(signer);
        if (tokens.isEmpty()) {
            throw new Failure(CRYPTO_ERROR, "CMS signer has no signature timestamp token");
        }

        Date earliest = null;
        for (TimeStampToken token : tokens) {
            Date time = validateTimestamp(token, signer.getSignature(), available);
            if (earliest == null || time.before(earliest)) {
                earliest = time;
            }
        }
        return earliest;
    }

    private TimeStampToken requestTimestamp(byte[] signature) throws Exception {
        if (authorityURL.isEmpty()) {
            throw new Failure(INVALID_ARGUMENT, "No timestamp authority URL is configured");
        }

        byte[] digest = MessageDigest.getInstance("SHA-256", PROVIDER).digest(signature);
        BigInteger nonce = new BigInteger(160, new SecureRandom()).setBit(159);
        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true);
        TimeStampRequest request =
                generator.generate(CMSSignedGenerator.DIGEST_SHA256, digest, nonce);

        long requestedAt = System.currentTimeMillis();
        byte[] encoded = transport.fetch("TSP", authorityURL, request.getEncoded());
        singleASN1(encoded);
        TimeStampResponse response = new TimeStampResponse(encoded);
        validateResponse(response, request, nonce, requestedAt);

        TimeStampToken token = response.getTimeStampToken();
        validateTimestamp(token, signature, CmsSupport.availableCertificates(validation, null));
        return token;
    }

    private static void validateResponse(
            TimeStampResponse response,
            TimeStampRequest request,
            BigInteger nonce,
            long requestedAt)
            throws Exception {
        boolean granted = response.getStatus() == 0 || response.getStatus() == 1;
        if (!granted || response.getFailInfo() != null || response.getTimeStampToken() == null) {
            throw new Failure(
                    CRYPTO_ERROR, "Timestamp authority did not grant the timestamp request");
        }

        // Checks the nonce, requested digest algorithm, imprint and response consistency.
        response.validate(request);
        TimeStampTokenInfo info = response.getTimeStampToken().getTimeStampInfo();
        if (!nonce.equals(info.getNonce())) {
            throw new Failure(CRYPTO_ERROR, "Timestamp nonce does not match the request");
        }
        if (info.getGenTime().getTime() < requestedAt - CLOCK_SKEW) {
            throw new Failure(CRYPTO_ERROR, "Timestamp response predates the request");
        }
    }

    private static List<TimeStampToken> timestampTokens(SignerInformation signer) throws Exception {
        AttributeTable unsigned = signer.getUnsignedAttributes();
        if (unsigned == null) {
            return Collections.emptyList();
        }
        if (unsigned.getAll(CMSAttributes.counterSignature).size() != 0) {
            throw new Failure(UNSUPPORTED, "CMS countersignatures are unsupported");
        }

        ASN1EncodableVector attributes = unsigned.getAll(SIGNATURE_TIMESTAMP);
        if (attributes.size() == 0) {
            return Collections.emptyList();
        }
        if (attributes.size() != 1) {
            throw new Failure(
                    CRYPTO_ERROR, "CMS contains duplicate signature timestamp attributes");
        }

        Attribute attribute = Attribute.getInstance(attributes.get(0));
        if (attribute.getAttrValues().size() == 0) {
            throw new Failure(CRYPTO_ERROR, "CMS timestamp attribute is empty");
        }
        List<TimeStampToken> tokens = new ArrayList<>();
        for (int index = 0; index < attribute.getAttrValues().size(); index++) {
            ContentInfo content =
                    ContentInfo.getInstance(attribute.getAttrValues().getObjectAt(index));
            tokens.add(new TimeStampToken(content));
        }
        return tokens;
    }

    private Date validateTimestamp(
            TimeStampToken token, byte[] signature, List<X509Certificate> available)
            throws Exception {
        CMSSignedData cms = token.toCMSSignedData();
        SignerInformation signer = validateTokenStructure(token, cms);
        TimeStampTokenInfo info = token.getTimeStampInfo();
        validateTokenInfo(info, signature);

        List<X509Certificate> certificates = new ArrayList<>(available);
        certificates.addAll(CmsSupport.availableCertificates(validation, cms));
        X509Certificate certificate = CmsSupport.signerCertificate(signer, certificates);
        validateTsaCertificate(certificate, info);

        // The provider checks ESSCertID/ESSCertIDv2, issuer/serial, genTime validity
        // and the TSA CMS signature after strict attribute validation.
        token.validate(certificate, PROVIDER);
        List<X509Certificate> chain =
                validation.validateChain(
                        certificate, certificates, false, info.getGenTime(), "TSA certificate");
        validation.checkRevocation(chain);
        return info.getGenTime();
    }

    private static SignerInformation validateTokenStructure(TimeStampToken token, CMSSignedData cms)
            throws Exception {
        ASN1Sequence info = ASN1Sequence.getInstance(singleASN1(CmsSupport.attachedContent(cms)));
        if (!DERInteger.getInstance(info.getObjectAt(0)).getValue().equals(BigInteger.ONE)) {
            throw new Failure(CRYPTO_ERROR, "Unsupported timestamp token version");
        }

        List<SignerInformation> signers = CmsSupport.orderedSigners(cms, token.getEncoded());
        if (signers.size() != 1) {
            throw new Failure(CRYPTO_ERROR, "Timestamp token must have exactly one signer");
        }
        SignerInformation signer = signers.get(0);
        CmsSupport.validateSignedAttributes(signer, cms.getSignedContentTypeOID());
        validateTimestampAttributes(signer);
        return signer;
    }

    private static void validateTimestampAttributes(SignerInformation signer) throws Failure {
        AttributeTable signed = signer.getSignedAttributes();
        if (signed == null
                || signed.getAll(CMSAttributes.contentType).size() != 1
                || signed.getAll(CMSAttributes.messageDigest).size() != 1
                || signed.getAll(SIGNING_CERTIFICATE).size()
                                + signed.getAll(SIGNING_CERTIFICATE_V2).size()
                        != 1) {
            throw new Failure(CRYPTO_ERROR, "Timestamp signed attributes are missing or ambiguous");
        }

        Attribute signingCertificate = signed.get(SIGNING_CERTIFICATE);
        if (signingCertificate == null) {
            signingCertificate = signed.get(SIGNING_CERTIFICATE_V2);
        }
        if (signingCertificate.getAttrValues().size() != 1) {
            throw new Failure(CRYPTO_ERROR, "Timestamp signing certificate attribute is ambiguous");
        }

        AttributeTable unsigned = signer.getUnsignedAttributes();
        if (unsigned != null
                && (unsigned.getAll(SIGNATURE_TIMESTAMP).size() != 0
                        || unsigned.getAll(CMSAttributes.counterSignature).size() != 0)) {
            throw new Failure(
                    UNSUPPORTED,
                    "Nested timestamps and timestamp countersignatures are unsupported");
        }
    }

    private static void validateTokenInfo(TimeStampTokenInfo info, byte[] signature)
            throws Exception {
        X509Extensions extensions = info.toTSTInfo().getExtensions();
        if (extensions != null) {
            for (Enumeration<?> ids = extensions.oids(); ids.hasMoreElements(); ) {
                DERObjectIdentifier id = (DERObjectIdentifier) ids.nextElement();
                if (extensions.getExtension(id).isCritical()) {
                    throw new Failure(
                            UNSUPPORTED, "Critical timestamp token extensions are unsupported");
                }
            }
        }
        if (info.getGenTime().getTime() > System.currentTimeMillis() + CLOCK_SKEW) {
            throw new Failure(CRYPTO_ERROR, "Timestamp generation time is in the future");
        }

        byte[] digest =
                MessageDigest.getInstance(info.getMessageImprintAlgOID(), PROVIDER)
                        .digest(signature);
        if (!MessageDigest.isEqual(digest, info.getMessageImprintDigest())) {
            throw new Failure(
                    CRYPTO_ERROR, "Timestamp message imprint does not match the CMS signature");
        }
    }

    private static void validateTsaCertificate(X509Certificate certificate, TimeStampTokenInfo info)
            throws Exception {
        List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
        if (extendedKeyUsage == null
                || extendedKeyUsage.size() != 1
                || !extendedKeyUsage.contains(TIMESTAMPING_EKU)
                || certificate.getCriticalExtensionOIDs() == null
                || !certificate.getCriticalExtensionOIDs().contains(EXTENDED_KEY_USAGE)) {
            throw new Failure(
                    CRYPTO_ERROR,
                    "Timestamp signer requires an exclusive critical timeStamping extended key"
                            + " usage");
        }
        requireDigitalSignature(certificate, "Timestamp signer");

        GeneralName authorityName = info.getTsa();
        if (authorityName == null) {
            return;
        }
        if (authorityName.getTagNo() != GeneralName.directoryName) {
            throw new Failure(UNSUPPORTED, "Only directoryName timestamp TSA names are supported");
        }
        X500Principal claimed =
                new X500Principal(authorityName.getName().getDERObject().getEncoded());
        if (!claimed.equals(certificate.getSubjectX500Principal())) {
            throw new Failure(
                    CRYPTO_ERROR, "Timestamp TSA name does not match its signer certificate");
        }
    }
}
